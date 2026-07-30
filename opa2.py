#!/usr/bin/python3

import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import warnings

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtensionOID,
)


warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning,
)

ZABBIX_TIMEOUT = float(os.getenv("SSL_CHECKER_ZABBIX_TIMEOUT", "10"))
HTTP_TIMEOUT = float(os.getenv("SSL_CHECKER_HTTP_TIMEOUT", "10"))
TOTAL_TIMEOUT = float(os.getenv("SSL_CHECKER_TOTAL_TIMEOUT", "50"))
MAX_WORKERS = max(1, int(os.getenv("SSL_CHECKER_MAX_WORKERS", "4")))

CACHE_DIR = os.getenv(
    "SSL_CHECKER_CACHE_DIR",
    "/var/tmp/ssl-checker-cache",
)
ISSUER_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_ISSUER_CACHE_TTL", "86400")
)
CRL_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_CRL_CACHE_TTL", "300")
)
OCSP_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_OCSP_CACHE_TTL", "300")
)

MAX_ISSUER_BYTES = int(
    os.getenv("SSL_CHECKER_MAX_ISSUER_BYTES", str(5 * 1024 * 1024))
)
MAX_OCSP_BYTES = int(
    os.getenv("SSL_CHECKER_MAX_OCSP_BYTES", str(1024 * 1024))
)
MAX_CRL_BYTES = int(
    os.getenv("SSL_CHECKER_MAX_CRL_BYTES", str(128 * 1024 * 1024))
)


class TotalTimeoutError(TimeoutError):
    pass


class ResponseTooLargeError(RuntimeError):
    pass


class Deadline:
    def __init__(self, timeout):
        self._expires_at = time.monotonic() + timeout

    def remaining(self, per_operation_timeout=None):
        seconds = self._expires_at - time.monotonic()

        if seconds <= 0:
            raise TotalTimeoutError("total execution timeout exceeded")

        if per_operation_timeout is None:
            return seconds

        return max(0.1, min(seconds, per_operation_timeout))


class FileCache:
    """
    A process-safe cache for binary HTTP responses.

    The lock is intentionally held while the first process downloads data.
    Other script_exporter processes wait for that result instead of creating
    a request storm against nginx and the remote CA infrastructure.
    """

    def __init__(self, directory):
        self.directory = directory
        self.enabled = self._prepare_directory()

    def _prepare_directory(self):
        try:
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
            return os.path.isdir(self.directory) and os.access(
                self.directory,
                os.R_OK | os.W_OK | os.X_OK,
            )
        except OSError:
            return False

    @staticmethod
    def _cache_key(method, url, data):
        digest = hashlib.sha256()
        digest.update(method.encode("ascii"))
        digest.update(b"\0")
        digest.update(url.encode("utf-8"))
        digest.update(b"\0")

        if data:
            digest.update(data)

        return digest.hexdigest()

    def _paths(self, key):
        return (
            os.path.join(self.directory, key + ".bin"),
            os.path.join(self.directory, key + ".lock"),
        )

    @staticmethod
    def _read_if_fresh(data_path, ttl):
        if ttl <= 0:
            return None

        try:
            age = time.time() - os.path.getmtime(data_path)

            if age < 0 or age > ttl:
                return None

            with open(data_path, "rb") as cached_file:
                return cached_file.read()
        except (FileNotFoundError, OSError):
            return None

    @staticmethod
    def _acquire_lock(lock_file, deadline):
        while True:
            try:
                fcntl.flock(
                    lock_file.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
                return
            except BlockingIOError:
                deadline.remaining()
                time.sleep(min(0.05, deadline.remaining()))

    def _write_atomic(self, data_path, data):
        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.directory,
                prefix=".ssl-checker-",
                delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
                os.chmod(temporary_path, 0o600)
                temporary_file.write(data)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            os.replace(temporary_path, data_path)
        finally:
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    def get_or_fetch(
        self,
        method,
        url,
        data,
        ttl,
        deadline,
        fetch,
    ):
        if not self.enabled or ttl <= 0:
            return fetch()

        key = self._cache_key(method, url, data)
        data_path, lock_path = self._paths(key)

        cached = self._read_if_fresh(data_path, ttl)
        if cached is not None:
            return cached

        with open(lock_path, "a+b") as lock_file:
            self._acquire_lock(lock_file, deadline)

            # Another process may have filled the cache while we waited.
            cached = self._read_if_fresh(data_path, ttl)
            if cached is not None:
                return cached

            result = fetch()
            self._write_atomic(data_path, result)
            return result


HTTP_CACHE = FileCache(CACHE_DIR)


def recv_exact(sock, size):
    chunks = []
    received = 0

    while received < size:
        chunk = sock.recv(size - received)

        if not chunk:
            raise ConnectionError(
                "Zabbix connection closed before the full response was read"
            )

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def zabbix_get(host, path, mode, port, deadline):
    key = f'vfs.file.{mode}["{path}"]'
    key_bytes = key.encode("UTF-8")

    try:
        timeout = deadline.remaining(ZABBIX_TIMEOUT)

        with socket.create_connection(
            (str(host), int(port)),
            timeout=timeout,
        ) as sock:
            sock.settimeout(timeout)

            request_header = struct.pack(
                "<4sBQ",
                b"ZBXD",
                1,
                len(key_bytes),
            )
            sock.sendall(request_header + key_bytes)

            response_header = recv_exact(sock, 13)
            header, version, length = struct.unpack(
                "<4sBQ",
                response_header,
            )

            if header != b"ZBXD" or version != 1:
                raise ValueError("invalid Zabbix response header")

            payload = recv_exact(sock, length)
            return response_header + payload
    except Exception:
        # Preserved for compatibility with the original control flow.
        return b"2"


def clean_zabbix_response(data, mode):
    text = data.decode("UTF-8", "ignore")

    if mode == "exists":
        text = re.sub(r"ZBXD.*?(?=\d+)", "", text)
    elif mode == "contents":
        text = re.sub(
            r"ZBXD.*?(?=-----BEGIN CERTIFICATE-----)",
            "",
            text,
            flags=re.S,
        )

    return text.strip().encode("UTF-8")


def build_gateway_url(target_url, gateway):
    parsed = urllib.parse.urlsplit(target_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported URL scheme: " + parsed.scheme)

    if not parsed.netloc:
        raise ValueError("Target URL has no host: " + target_url)

    target_path = parsed.path or "/"

    if parsed.query:
        target_path += "?" + parsed.query

    return (
        gateway.rstrip("/")
        + "/proxy/"
        + parsed.scheme
        + "/"
        + parsed.netloc
        + target_path
    )


def read_limited_response(response, maximum_bytes):
    content_length = response.headers.get("Content-Length")

    if content_length:
        try:
            if int(content_length) > maximum_bytes:
                raise ResponseTooLargeError(
                    f"response is larger than {maximum_bytes} bytes"
                )
        except ValueError:
            pass

    data = response.read(maximum_bytes + 1)

    if len(data) > maximum_bytes:
        raise ResponseTooLargeError(
            f"response is larger than {maximum_bytes} bytes"
        )

    return data


def gateway_request(
    target_url,
    gateway,
    deadline,
    method="GET",
    data=None,
    content_type=None,
    cache_ttl=0,
    maximum_bytes=MAX_CRL_BYTES,
):
    proxy_url = build_gateway_url(target_url, gateway)

    headers = {
        "User-Agent": "ssl-checker/1.0",
    }

    if content_type:
        headers["Content-Type"] = content_type

    if method == "POST":
        headers["Accept"] = "application/ocsp-response"

    def fetch():
        timeout = deadline.remaining(HTTP_TIMEOUT)
        request = urllib.request.Request(
            proxy_url,
            data=data,
            headers=headers,
            method=method,
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            return read_limited_response(response, maximum_bytes)

    return HTTP_CACHE.get_or_fetch(
        method=method,
        url=target_url,
        data=data,
        ttl=cache_ttl,
        deadline=deadline,
        fetch=fetch,
    )


def download_url(url, gateway, deadline, resource_type):
    if resource_type == "issuer":
        cache_ttl = ISSUER_CACHE_TTL
        maximum_bytes = MAX_ISSUER_BYTES
    elif resource_type == "crl":
        cache_ttl = CRL_CACHE_TTL
        maximum_bytes = MAX_CRL_BYTES
    else:
        raise ValueError("unsupported resource type: " + resource_type)

    return gateway_request(
        url,
        gateway,
        deadline,
        method="GET",
        cache_ttl=cache_ttl,
        maximum_bytes=maximum_bytes,
    )


def post_ocsp_request(ocsp_url, data, gateway, deadline):
    return gateway_request(
        ocsp_url,
        gateway,
        deadline,
        method="POST",
        data=data,
        content_type="application/ocsp-request",
        cache_ttl=OCSP_CACHE_TTL,
        maximum_bytes=MAX_OCSP_BYTES,
    )


def load_cert_from_data(data):
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_certificate(data, default_backend())


def load_crl_from_data(data):
    try:
        return x509.load_der_x509_crl(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_crl(data, default_backend())


def get_urls_from_extension(cert, oid):
    try:
        extension = cert.extensions.get_extension_for_oid(oid).value
        urls = []

        for point in extension:
            if point.full_name:
                for name in point.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)

        return urls
    except x509.ExtensionNotFound:
        return []


def get_aia_urls(cert):
    ocsp_urls = []
    issuer_urls = []

    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        for description in aia:
            if not isinstance(
                description.access_location,
                x509.UniformResourceIdentifier,
            ):
                continue

            if (
                description.access_method
                == AuthorityInformationAccessOID.OCSP
            ):
                ocsp_urls.append(description.access_location.value)
            elif (
                description.access_method
                == AuthorityInformationAccessOID.CA_ISSUERS
            ):
                issuer_urls.append(description.access_location.value)
    except x509.ExtensionNotFound:
        pass

    return ocsp_urls, issuer_urls


def get_authority_key_identifier(cert):
    try:
        authority_key_identifier = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value

        if authority_key_identifier.key_identifier:
            return authority_key_identifier.key_identifier.hex()
    except x509.ExtensionNotFound:
        pass

    return None


def get_subject_key_identifier(cert):
    try:
        subject_key_identifier = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        return subject_key_identifier.digest.hex()
    except x509.ExtensionNotFound:
        pass

    return None


def check_revocation_ocsp(
    cert,
    issuer_cert,
    ocsp_url,
    gateway,
    deadline,
):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        cert,
        issuer_cert,
        hashes.SHA1(),
    )
    request = builder.build()

    ocsp_request_data = request.public_bytes(serialization.Encoding.DER)
    ocsp_response_data = post_ocsp_request(
        ocsp_url,
        ocsp_request_data,
        gateway,
        deadline,
    )
    ocsp_response = ocsp.load_der_ocsp_response(ocsp_response_data)

    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {
            "method": "ocsp",
            "status": "unknown",
            "error": str(ocsp_response.response_status),
            "ocsp_url": ocsp_url,
            "issuer_url": None,
        }

    if ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return {
            "method": "ocsp",
            "status": "good",
            "error": None,
            "ocsp_url": ocsp_url,
            "issuer_url": None,
        }

    if ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return {
            "method": "ocsp",
            "status": "revoked",
            "error": None,
            "ocsp_url": ocsp_url,
            "issuer_url": None,
            "revocation_time": (
                ocsp_response.revocation_time.isoformat()
                if ocsp_response.revocation_time
                else None
            ),
            "revocation_reason": (
                str(ocsp_response.revocation_reason)
                if ocsp_response.revocation_reason
                else None
            ),
        }

    return {
        "method": "ocsp",
        "status": "unknown",
        "error": None,
        "ocsp_url": ocsp_url,
        "issuer_url": None,
    }


def _run_parallel_ordered(tasks):
    """
    Run callables concurrently and return (success, value) in input order.

    Deterministic ordering keeps checked_ocsp and checked_crl compatible with
    the original nested loops even though the network calls are concurrent.
    """

    if not tasks:
        return []

    worker_count = min(MAX_WORKERS, len(tasks))
    results = [None] * len(tasks)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="ssl-checker",
    ) as executor:
        future_to_index = {
            executor.submit(task): index
            for index, task in enumerate(tasks)
        }

        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]

            try:
                results[index] = (True, future.result())
            except Exception as error:
                results[index] = (False, str(error))

    return results


def _download_issuer(issuer_url, gateway, deadline):
    issuer_data = download_url(
        issuer_url,
        gateway,
        deadline,
        resource_type="issuer",
    )
    return load_cert_from_data(issuer_data)


def _check_one_ocsp(
    cert,
    issuer_cert,
    issuer_url,
    ocsp_url,
    gateway,
    deadline,
):
    result = check_revocation_ocsp(
        cert,
        issuer_cert,
        ocsp_url,
        gateway,
        deadline,
    )
    result["issuer_url"] = issuer_url
    return result


def _check_one_crl(cert, crl_url, gateway, deadline):
    crl_data = download_url(
        crl_url,
        gateway,
        deadline,
        resource_type="crl",
    )
    crl = load_crl_from_data(crl_data)
    revoked_cert = crl.get_revoked_certificate_by_serial_number(
        cert.serial_number
    )

    if revoked_cert is not None:
        return {
            "url": crl_url,
            "status": "revoked",
            "error": None,
            "revocation_date": revoked_cert.revocation_date.isoformat(),
        }

    return {
        "url": crl_url,
        "status": "good",
        "error": None,
        "revocation_date": None,
    }


def check_revocation_crl(
    cert,
    crl_urls,
    gateway,
    deadline,
):
    checked_crl = []
    last_error = None
    has_good = False

    tasks = [
        (
            lambda crl_url=crl_url: _check_one_crl(
                cert,
                crl_url,
                gateway,
                deadline,
            )
        )
        for crl_url in crl_urls
    ]
    results = _run_parallel_ordered(tasks)

    for crl_url, (success, value) in zip(crl_urls, results):
        if success:
            result = value
            checked_crl.append(result)

            if result["status"] == "revoked":
                return {
                    "status": "revoked",
                    "source_url": crl_url,
                    "revocation_date": result["revocation_date"],
                    "error": None,
                    "checked_crl": checked_crl,
                }

            has_good = True
        else:
            last_error = value
            checked_crl.append(
                {
                    "url": crl_url,
                    "status": "unknown",
                    "error": value,
                    "revocation_date": None,
                }
            )

    if has_good:
        return {
            "status": "good",
            "source_url": None,
            "revocation_date": None,
            "error": None,
            "checked_crl": checked_crl,
        }

    return {
        "status": "unknown",
        "source_url": None,
        "revocation_date": None,
        "error": last_error if last_error else "no crl urls",
        "checked_crl": checked_crl,
    }


def check_revocation(
    cert,
    ocsp_urls,
    issuer_urls,
    crl_urls,
    gateway,
    deadline,
):
    checked_ocsp = []
    checked_crl = []

    has_ocsp_good = False
    last_ocsp_error = None

    issuer_tasks = [
        (
            lambda issuer_url=issuer_url: _download_issuer(
                issuer_url,
                gateway,
                deadline,
            )
        )
        for issuer_url in issuer_urls
    ]
    issuer_results = _run_parallel_ordered(issuer_tasks)

    ocsp_tasks = []
    ocsp_task_positions = {}

    for issuer_index, issuer_url in enumerate(issuer_urls):
        success, value = issuer_results[issuer_index]

        if not success:
            continue

        issuer_cert = value

        for ocsp_index, ocsp_url in enumerate(ocsp_urls):
            task_index = len(ocsp_tasks)
            ocsp_task_positions[(issuer_index, ocsp_index)] = task_index
            ocsp_tasks.append(
                lambda issuer_cert=issuer_cert,
                issuer_url=issuer_url,
                ocsp_url=ocsp_url: _check_one_ocsp(
                    cert,
                    issuer_cert,
                    issuer_url,
                    ocsp_url,
                    gateway,
                    deadline,
                )
            )

    ocsp_results = _run_parallel_ordered(ocsp_tasks)

    # Consume results in exactly the order of the original nested loops.
    for issuer_index, issuer_url in enumerate(issuer_urls):
        issuer_success, issuer_value = issuer_results[issuer_index]

        if not issuer_success:
            last_ocsp_error = issuer_value
            checked_ocsp.append(
                {
                    "method": "ocsp",
                    "status": "unknown",
                    "error": issuer_value,
                    "ocsp_url": None,
                    "issuer_url": issuer_url,
                }
            )
            continue

        for ocsp_index, ocsp_url in enumerate(ocsp_urls):
            result_index = ocsp_task_positions[
                (issuer_index, ocsp_index)
            ]
            success, value = ocsp_results[result_index]

            if success:
                result = value
                checked_ocsp.append(result)

                if result["status"] == "revoked":
                    return {
                        "method": "ocsp",
                        "status": "revoked",
                        "source_url": ocsp_url,
                        "issuer_url": issuer_url,
                        "revocation_time": result.get(
                            "revocation_time"
                        ),
                        "revocation_reason": result.get(
                            "revocation_reason"
                        ),
                        "error": None,
                        "checked_ocsp": checked_ocsp,
                        "checked_crl": checked_crl,
                    }

                if result["status"] == "good":
                    has_ocsp_good = True
            else:
                last_ocsp_error = value
                checked_ocsp.append(
                    {
                        "method": "ocsp",
                        "status": "unknown",
                        "error": value,
                        "ocsp_url": ocsp_url,
                        "issuer_url": issuer_url,
                    }
                )

    if has_ocsp_good:
        return {
            "method": "ocsp",
            "status": "good",
            "source_url": None,
            "issuer_url": None,
            "revocation_time": None,
            "revocation_reason": None,
            "error": None,
            "checked_ocsp": checked_ocsp,
            "checked_crl": checked_crl,
        }

    crl_result = check_revocation_crl(
        cert,
        crl_urls,
        gateway,
        deadline,
    )
    checked_crl = crl_result["checked_crl"]

    if crl_result["status"] == "revoked":
        return {
            "method": "crl",
            "status": "revoked",
            "source_url": crl_result["source_url"],
            "issuer_url": None,
            "revocation_time": crl_result["revocation_date"],
            "revocation_reason": None,
            "error": None,
            "checked_ocsp": checked_ocsp,
            "checked_crl": checked_crl,
        }

    if crl_result["status"] == "good":
        return {
            "method": "crl",
            "status": "good",
            "source_url": crl_result["source_url"],
            "issuer_url": None,
            "revocation_time": None,
            "revocation_reason": None,
            "error": None,
            "checked_ocsp": checked_ocsp,
            "checked_crl": checked_crl,
        }

    return {
        "method": "none",
        "status": "unknown",
        "source_url": None,
        "issuer_url": None,
        "revocation_time": None,
        "revocation_reason": None,
        "error": crl_result.get("error") or last_ocsp_error,
        "checked_ocsp": checked_ocsp,
        "checked_crl": checked_crl,
    }


def get_cert(pem_data, gateway, deadline):
    try:
        cert = x509.load_pem_x509_certificate(
            pem_data,
            default_backend(),
        )

        not_after = cert.not_valid_after
        timestamp_after = time.mktime(
            datetime.datetime.strptime(
                str(not_after),
                "%Y-%m-%d %H:%M:%S",
            ).timetuple()
        )

        timestamp_now = time.time()
        timestamp_diff = int(timestamp_after) - int(timestamp_now)
        days_left = int(timestamp_diff / 86400)

        ocsp_urls, issuer_urls = get_aia_urls(cert)
        crl_urls = get_urls_from_extension(
            cert,
            ExtensionOID.CRL_DISTRIBUTION_POINTS,
        )

        revocation = check_revocation(
            cert=cert,
            ocsp_urls=ocsp_urls,
            issuer_urls=issuer_urls,
            crl_urls=crl_urls,
            gateway=gateway,
            deadline=deadline,
        )

        result = {
            "days_left": days_left,
            "serial_number": format(cert.serial_number, "x").upper(),
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat(),
            "ocsp_urls": ocsp_urls,
            "crl_urls": crl_urls,
            "issuer_urls": issuer_urls,
            "authority_key_identifier": get_authority_key_identifier(cert),
            "subject_key_identifier": get_subject_key_identifier(cert),
            "revocation": revocation,
        }

        print(json.dumps(result, ensure_ascii=False, indent=1))
    except Exception as error:
        print(
            json.dumps(
                {
                    "error": "cert_parse_error",
                    "message": str(error),
                },
                ensure_ascii=False,
                indent=1,
            )
        )


def main():
    if len(sys.argv) != 5:
        print(
            json.dumps(
                {
                    "error": "usage",
                    "message": (
                        "Usage: ssl_container_new.py "
                        "<path> <host> <port> <gateway>"
                    ),
                },
                ensure_ascii=False,
                indent=1,
            )
        )
        return 1

    path = sys.argv[1]
    host = sys.argv[2]
    port = sys.argv[3]
    gateway = sys.argv[4]
    deadline = Deadline(TOTAL_TIMEOUT)

    mode = "exists"
    check_file_exist = clean_zabbix_response(
        zabbix_get(host, path, mode, port, deadline),
        mode,
    )

    if check_file_exist.decode("UTF-8", "ignore") == "1":
        mode = "contents"
        pem_data = clean_zabbix_response(
            zabbix_get(host, path, mode, port, deadline),
            mode,
        )
        get_cert(pem_data, gateway, deadline)
    elif check_file_exist.decode("UTF-8", "ignore") == "2":
        print(
            json.dumps(
                {
                    "error": "zabbix_not_supported",
                },
                ensure_ascii=False,
                indent=1,
            )
        )
    else:
        print(
            json.dumps(
                {
                    "error": "certificate_file_not_found",
                },
                ensure_ascii=False,
                indent=1,
            )
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
