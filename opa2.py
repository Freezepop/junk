#!/usr/bin/env python3

"""
Fast compatibility-oriented OCSP/CRL checker for a Zabbix external check.

Interface:
    ssl_revocation_checker.py <path> <agent_host> <agent_port> <gateway>

The result-selection policy intentionally matches the original checker:
    1. OCSP revoked
    2. OCSP good
    3. CRL revoked
    4. CRL good
    5. unknown

The speed-up comes from parallel I/O, bounded deadlines and caching, not from
changing which successful response is accepted.
"""

import datetime
import fcntl
import hashlib
import json
import math
import os
import queue
import re
import signal
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


warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


# The Zabbix proxy kills external checks at 30 seconds. Leave a safety margin.
TOTAL_TIMEOUT = float(os.getenv("SSL_CHECKER_TOTAL_TIMEOUT", "26"))
HARD_TIMEOUT = float(os.getenv("SSL_CHECKER_HARD_TIMEOUT", "28"))
ZABBIX_TIMEOUT = float(os.getenv("SSL_CHECKER_ZABBIX_TIMEOUT", "3"))

# Issuer and OCSP are sequential inside one OCSP path, but different issuer
# mirrors run in parallel. CRL mirrors start at the same time as OCSP paths.
ISSUER_TIMEOUT = float(os.getenv("SSL_CHECKER_ISSUER_TIMEOUT", "10"))
OCSP_TIMEOUT = float(os.getenv("SSL_CHECKER_OCSP_TIMEOUT", "10"))
CRL_TIMEOUT = float(os.getenv("SSL_CHECKER_CRL_TIMEOUT", "15"))

CACHE_DIR = os.getenv(
    "SSL_CHECKER_CACHE_DIR",
    "/var/tmp/ssl-checker-cache",
)
ISSUER_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_ISSUER_CACHE_TTL", "604800")
)
OCSP_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_OCSP_CACHE_TTL", "300")
)
CRL_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_CRL_CACHE_TTL", "900")
)
RESULT_CACHE_TTL = float(
    os.getenv("SSL_CHECKER_RESULT_CACHE_TTL", "300")
)

MAX_CERT_FILE_BYTES = int(
    os.getenv("SSL_CHECKER_MAX_CERT_FILE_BYTES", str(5 * 1024 * 1024))
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

PEM_CERTIFICATE_RE = re.compile(
    br"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
UTC = datetime.timezone.utc


class CheckError(RuntimeError):
    pass


class Deadline:
    def __init__(self, seconds):
        self.expires_at = time.monotonic() + float(seconds)

    def remaining(self):
        value = self.expires_at - time.monotonic()
        if value <= 0:
            raise TimeoutError("total execution timeout exceeded")
        return value


def error_text(error):
    text = str(error).strip()
    return text if text else error.__class__.__name__


def as_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def utc_property(obj, aware_name, legacy_name):
    value = getattr(obj, aware_name, None)
    if value is None:
        value = getattr(obj, legacy_name, None)
    return as_utc(value)


def emit(payload):
    signal.setitimer(signal.ITIMER_REAL, 0)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=1))
    sys.stdout.write("\n")
    sys.stdout.flush()


def hard_timeout_handler(_signum, _frame):
    payload = {
        "error": "total_timeout",
        "message": "hard execution timeout exceeded",
        "revocation": {
            "method": "none",
            "status": "unknown",
            "source_url": None,
            "issuer_url": None,
            "revocation_time": None,
            "revocation_reason": None,
            "error": "hard execution timeout exceeded",
            "checked_ocsp": [],
            "checked_crl": [],
        },
    }
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    os.write(sys.stdout.fileno(), data)
    os._exit(0)


class DiskCache:
    """Small process-safe cache for successful HTTP responses and results."""

    def __init__(self, directory):
        self.directory = directory
        self.enabled = self._prepare()

    def _prepare(self):
        try:
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
            return os.path.isdir(self.directory) and os.access(
                self.directory,
                os.R_OK | os.W_OK | os.X_OK,
            )
        except OSError:
            return False

    @staticmethod
    def make_key(*parts):
        digest = hashlib.sha256()
        for part in parts:
            if part is None:
                part = b""
            elif not isinstance(part, bytes):
                part = str(part).encode("utf-8")
            digest.update(part)
            digest.update(b"\0")
        return digest.hexdigest()

    def paths(self, key, suffix):
        return (
            os.path.join(self.directory, key + suffix),
            os.path.join(self.directory, key + ".lock"),
        )

    @staticmethod
    def read_fresh(path, ttl):
        if ttl <= 0:
            return None
        try:
            age = time.time() - os.path.getmtime(path)
            if age < 0 or age > ttl:
                return None
            with open(path, "rb") as source:
                return source.read()
        except (FileNotFoundError, OSError):
            return None

    @staticmethod
    def atomic_write(directory, path, data):
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=directory,
                prefix=".ssl-checker-",
                delete=False,
            ) as temporary:
                temporary_path = temporary.name
                os.chmod(temporary_path, 0o600)
                temporary.write(data)
                temporary.flush()
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    def get_or_fetch(self, key, ttl, fetch):
        if not self.enabled or ttl <= 0:
            return fetch(), False

        data_path, lock_path = self.paths(key, ".bin")
        cached = self.read_fresh(data_path, ttl)
        if cached is not None:
            return cached, True

        with open(lock_path, "a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            cached = self.read_fresh(data_path, ttl)
            if cached is not None:
                return cached, True

            data = fetch()
            self.atomic_write(self.directory, data_path, data)
            return data, False

    def read_json(self, key, ttl):
        if not self.enabled or ttl <= 0:
            return None
        path, _lock_path = self.paths(key, ".json")
        data = self.read_fresh(path, ttl)
        if data is None:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def write_json(self, key, payload):
        if not self.enabled:
            return
        path, _lock_path = self.paths(key, ".json")
        data = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.atomic_write(self.directory, path, data)


HTTP_CACHE = DiskCache(os.path.join(CACHE_DIR, "http"))
RESULT_CACHE = DiskCache(os.path.join(CACHE_DIR, "result"))


def recv_exact(sock, length, deadline):
    chunks = []
    received = 0
    while received < length:
        sock.settimeout(deadline.remaining())
        chunk = sock.recv(length - received)
        if not chunk:
            raise CheckError("Zabbix connection closed unexpectedly")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def read_certificate_from_zabbix(host, path, port):
    deadline = Deadline(ZABBIX_TIMEOUT)
    escaped_path = path.replace("\\", "\\\\").replace('"', '\\"')
    key = 'vfs.file.contents["{}"]'.format(escaped_path).encode("utf-8")
    request = struct.pack("<4sBQ", b"ZBXD", 1, len(key)) + key

    with socket.create_connection(
        (str(host), int(port)),
        timeout=deadline.remaining(),
    ) as sock:
        sock.settimeout(deadline.remaining())
        sock.sendall(request)
        header = recv_exact(sock, 13, deadline)
        magic, version, length = struct.unpack("<4sBQ", header)
        if magic != b"ZBXD" or version != 1:
            raise CheckError("invalid Zabbix response header")
        if length > MAX_CERT_FILE_BYTES:
            raise CheckError("certificate file is too large")
        payload = recv_exact(sock, length, deadline)

    if payload.startswith(b"ZBX_NOTSUPPORTED"):
        parts = payload.split(b"\0", 1)
        message = (
            parts[1].decode("utf-8", "replace")
            if len(parts) == 2
            else "vfs.file.contents is not supported"
        )
        raise CheckError(message)
    return payload


def build_gateway_url(target_url, gateway):
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme not in ("http", "https"):
        raise CheckError("Unsupported URL scheme: " + parsed.scheme)
    if not parsed.netloc:
        raise CheckError("Target URL has no host: " + target_url)

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


def read_limited(response, maximum_bytes):
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > maximum_bytes:
                raise CheckError("HTTP response is too large")
        except ValueError:
            pass

    data = response.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise CheckError("HTTP response is too large")
    return data


def gateway_request(
    target_url,
    gateway,
    timeout,
    maximum_bytes,
    cache_ttl,
    method="GET",
    body=None,
    content_type=None,
):
    cache_key = HTTP_CACHE.make_key(method, target_url, body)

    def fetch():
        headers = {"User-Agent": "ssl-checker/2.1"}
        if content_type:
            headers["Content-Type"] = content_type
        if method == "POST":
            headers["Accept"] = "application/ocsp-response"

        request = urllib.request.Request(
            build_gateway_url(target_url, gateway),
            data=body,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return read_limited(response, maximum_bytes)

    return HTTP_CACHE.get_or_fetch(cache_key, cache_ttl, fetch)


def download_issuer(url, gateway):
    return gateway_request(
        url,
        gateway,
        ISSUER_TIMEOUT,
        MAX_ISSUER_BYTES,
        ISSUER_CACHE_TTL,
    )


def post_ocsp(url, request_data, gateway):
    return gateway_request(
        url,
        gateway,
        OCSP_TIMEOUT,
        MAX_OCSP_BYTES,
        OCSP_CACHE_TTL,
        method="POST",
        body=request_data,
        content_type="application/ocsp-request",
    )


def download_crl(url, gateway):
    return gateway_request(
        url,
        gateway,
        CRL_TIMEOUT,
        MAX_CRL_BYTES,
        CRL_CACHE_TTL,
    )


def load_certificates(data):
    blocks = PEM_CERTIFICATE_RE.findall(data)
    if blocks:
        return [
            x509.load_pem_x509_certificate(block, default_backend())
            for block in blocks
        ]
    return [x509.load_der_x509_certificate(data, default_backend())]


def load_issuer(data):
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_certificate(data, default_backend())


def load_crl(data):
    try:
        return x509.load_der_x509_crl(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_crl(data, default_backend())


def get_aia_urls(certificate):
    ocsp_urls = []
    issuer_urls = []
    try:
        aia = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return ocsp_urls, issuer_urls

    for description in aia:
        location = description.access_location
        if not isinstance(location, x509.UniformResourceIdentifier):
            continue
        if description.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(location.value)
        elif (
            description.access_method
            == AuthorityInformationAccessOID.CA_ISSUERS
        ):
            issuer_urls.append(location.value)

    return list(dict.fromkeys(ocsp_urls)), list(dict.fromkeys(issuer_urls))


def get_crl_urls(certificate):
    urls = []
    try:
        points = certificate.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return urls

    for point in points:
        if not point.full_name:
            continue
        for name in point.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return list(dict.fromkeys(urls))


def get_authority_key_identifier(certificate):
    try:
        value = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value
        if value.key_identifier:
            return value.key_identifier.hex()
    except x509.ExtensionNotFound:
        pass
    return None


def get_subject_key_identifier(certificate):
    try:
        value = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        return value.digest.hex()
    except x509.ExtensionNotFound:
        return None


def find_local_issuer(leaf, certificates):
    for candidate in certificates[1:]:
        if candidate.subject == leaf.issuer:
            return candidate
    return None


def make_ocsp_result(
    status,
    ocsp_url,
    issuer_url,
    error=None,
    revocation_time=None,
    revocation_reason=None,
    cached=False,
):
    result = {
        "method": "ocsp",
        "status": status,
        "error": error,
        "ocsp_url": ocsp_url,
        "issuer_url": issuer_url,
        "cached": cached,
    }
    if revocation_time is not None:
        result["revocation_time"] = revocation_time
    if revocation_reason is not None:
        result["revocation_reason"] = revocation_reason
    return result


def check_ocsp(leaf, issuer, ocsp_url, issuer_url, gateway):
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, issuer, hashes.SHA1())
        .build()
    )
    request_data = request.public_bytes(serialization.Encoding.DER)
    response_data, cached = post_ocsp(ocsp_url, request_data, gateway)
    response = ocsp.load_der_ocsp_response(response_data)

    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return make_ocsp_result(
            "unknown",
            ocsp_url,
            issuer_url,
            error=str(response.response_status),
            cached=cached,
        )

    if response.serial_number != leaf.serial_number:
        return make_ocsp_result(
            "unknown",
            ocsp_url,
            issuer_url,
            error="OCSP response serial does not match certificate",
            cached=cached,
        )

    if response.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return make_ocsp_result(
            "good",
            ocsp_url,
            issuer_url,
            cached=cached,
        )

    if response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        revocation_time = utc_property(
            response,
            "revocation_time_utc",
            "revocation_time",
        )
        return make_ocsp_result(
            "revoked",
            ocsp_url,
            issuer_url,
            revocation_time=(
                revocation_time.isoformat() if revocation_time else None
            ),
            revocation_reason=(
                str(response.revocation_reason)
                if response.revocation_reason is not None
                else None
            ),
            cached=cached,
        )

    return make_ocsp_result(
        "unknown",
        ocsp_url,
        issuer_url,
        cached=cached,
    )


def make_crl_result(
    url,
    status,
    error=None,
    revocation_date=None,
    cached=False,
):
    return {
        "url": url,
        "status": status,
        "error": error,
        "revocation_date": revocation_date,
        "cached": cached,
    }


def check_crl(leaf, crl_url, gateway):
    crl_data, cached = download_crl(crl_url, gateway)
    crl = load_crl(crl_data)

    # This indexed lookup is substantially faster than iterating a large CRL.
    revoked = crl.get_revoked_certificate_by_serial_number(
        leaf.serial_number
    )
    if revoked is not None:
        revocation_date = utc_property(
            revoked,
            "revocation_date_utc",
            "revocation_date",
        )
        return make_crl_result(
            crl_url,
            "revoked",
            revocation_date=(
                revocation_date.isoformat() if revocation_date else None
            ),
            cached=cached,
        )

    return make_crl_result(crl_url, "good", cached=cached)


def ocsp_worker(
    event_queue,
    task_index,
    leaf,
    local_issuer,
    issuer_url,
    ocsp_url,
    gateway,
):
    try:
        issuer = local_issuer
        if issuer is None:
            issuer_data, _cached = download_issuer(issuer_url, gateway)
            issuer = load_issuer(issuer_data)
        result = check_ocsp(
            leaf,
            issuer,
            ocsp_url,
            issuer_url,
            gateway,
        )
    except Exception as error:
        result = make_ocsp_result(
            "unknown",
            ocsp_url,
            issuer_url,
            error=error_text(error),
        )
    event_queue.put(("ocsp", task_index, result))


def crl_worker(event_queue, task_index, leaf, crl_url, gateway):
    try:
        result = check_crl(leaf, crl_url, gateway)
    except Exception as error:
        result = make_crl_result(
            crl_url,
            "unknown",
            error=error_text(error),
        )
    event_queue.put(("crl", task_index, result))


def ordered_results(result_map, count):
    return [
        result_map[index]
        for index in range(count)
        if index in result_map
    ]


def select_revocation(checked_ocsp, checked_crl, partial=False):
    ocsp_revoked = next(
        (
            item
            for item in checked_ocsp
            if item["status"] == "revoked"
        ),
        None,
    )
    if ocsp_revoked:
        return {
            "method": "ocsp",
            "status": "revoked",
            "source_url": ocsp_revoked["ocsp_url"],
            "issuer_url": ocsp_revoked["issuer_url"],
            "revocation_time": ocsp_revoked.get("revocation_time"),
            "revocation_reason": ocsp_revoked.get("revocation_reason"),
            "error": None,
            "checked_ocsp": checked_ocsp,
            "checked_crl": checked_crl,
            "partial": partial,
        }

    ocsp_good = next(
        (item for item in checked_ocsp if item["status"] == "good"),
        None,
    )
    if ocsp_good:
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
            "partial": partial,
        }

    crl_revoked = next(
        (item for item in checked_crl if item["status"] == "revoked"),
        None,
    )
    if crl_revoked:
        return {
            "method": "crl",
            "status": "revoked",
            "source_url": crl_revoked["url"],
            "issuer_url": None,
            "revocation_time": crl_revoked.get("revocation_date"),
            "revocation_reason": None,
            "error": None,
            "checked_ocsp": checked_ocsp,
            "checked_crl": checked_crl,
            "partial": partial,
        }

    crl_good = next(
        (item for item in checked_crl if item["status"] == "good"),
        None,
    )
    if crl_good:
        return {
            "method": "crl",
            "status": "good",
            "source_url": None,
            "issuer_url": None,
            "revocation_time": None,
            "revocation_reason": None,
            "error": None,
            "checked_ocsp": checked_ocsp,
            "checked_crl": checked_crl,
            "partial": partial,
        }

    errors = [
        item["error"]
        for item in checked_ocsp + checked_crl
        if item.get("error")
    ]
    return {
        "method": "none",
        "status": "unknown",
        "source_url": None,
        "issuer_url": None,
        "revocation_time": None,
        "revocation_reason": None,
        "error": errors[-1] if errors else "no usable OCSP or CRL response",
        "checked_ocsp": checked_ocsp,
        "checked_crl": checked_crl,
        "partial": partial,
    }


def check_revocation(
    leaf,
    certificates,
    ocsp_urls,
    issuer_urls,
    crl_urls,
    gateway,
    total_deadline,
):
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    cached = RESULT_CACHE.read_json(fingerprint, RESULT_CACHE_TTL)
    if cached and cached.get("status") in ("good", "revoked"):
        cached["cached"] = True
        return cached

    local_issuer = find_local_issuer(leaf, certificates)
    if local_issuer is not None:
        issuer_sources = [(local_issuer, "local-chain")]
    else:
        issuer_sources = [(None, url) for url in issuer_urls]

    ocsp_tasks = []
    for local_certificate, issuer_url in issuer_sources:
        for ocsp_url in ocsp_urls:
            ocsp_tasks.append(
                (local_certificate, issuer_url, ocsp_url)
            )

    events = queue.Queue()
    for index, task in enumerate(ocsp_tasks):
        local_certificate, issuer_url, ocsp_url = task
        threading.Thread(
            target=ocsp_worker,
            args=(
                events,
                index,
                leaf,
                local_certificate,
                issuer_url,
                ocsp_url,
                gateway,
            ),
            name="ssl-ocsp-{}".format(index),
            daemon=True,
        ).start()

    for index, crl_url in enumerate(crl_urls):
        threading.Thread(
            target=crl_worker,
            args=(events, index, leaf, crl_url, gateway),
            name="ssl-crl-{}".format(index),
            daemon=True,
        ).start()

    ocsp_results = {}
    crl_results = {}
    ocsp_count = len(ocsp_tasks)
    crl_count = len(crl_urls)

    while True:
        ocsp_complete = len(ocsp_results) == ocsp_count
        crl_complete = len(crl_results) == crl_count
        checked_ocsp = ordered_results(ocsp_results, ocsp_count)
        checked_crl = ordered_results(crl_results, crl_count)

        # Match the original priority. CRL downloads may already be complete,
        # but they are used only when all OCSP paths have finished without a
        # decisive answer.
        if ocsp_complete:
            decisive_ocsp = any(
                item["status"] in ("good", "revoked")
                for item in checked_ocsp
            )
            if decisive_ocsp or crl_complete:
                result = select_revocation(
                    checked_ocsp,
                    checked_crl,
                )
                break

        try:
            remaining = total_deadline.remaining()
        except TimeoutError:
            result = select_revocation(
                checked_ocsp,
                checked_crl,
                partial=not (ocsp_complete and crl_complete),
            )
            break

        try:
            kind, index, value = events.get(
                timeout=min(0.25, remaining)
            )
        except queue.Empty:
            continue

        if kind == "ocsp":
            ocsp_results[index] = value
        else:
            crl_results[index] = value

    if (
        result["status"] == "revoked"
        or (
            result["status"] == "good"
            and not result.get("partial", False)
        )
    ):
        result["cached"] = False
        RESULT_CACHE.write_json(fingerprint, result)
    return result


def certificate_result(pem_data, gateway, total_deadline):
    certificates = load_certificates(pem_data)
    leaf = certificates[0]
    not_before = utc_property(
        leaf,
        "not_valid_before_utc",
        "not_valid_before",
    )
    not_after = utc_property(
        leaf,
        "not_valid_after_utc",
        "not_valid_after",
    )
    days_left = math.floor(
        (not_after - datetime.datetime.now(UTC)).total_seconds() / 86400
    )

    ocsp_urls, issuer_urls = get_aia_urls(leaf)
    crl_urls = get_crl_urls(leaf)
    revocation = check_revocation(
        leaf,
        certificates,
        ocsp_urls,
        issuer_urls,
        crl_urls,
        gateway,
        total_deadline,
    )

    return {
        "days_left": days_left,
        "serial_number": format(leaf.serial_number, "x").upper(),
        "issuer": leaf.issuer.rfc4514_string(),
        "subject": leaf.subject.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "ocsp_urls": ocsp_urls,
        "crl_urls": crl_urls,
        "issuer_urls": issuer_urls,
        "authority_key_identifier": get_authority_key_identifier(leaf),
        "subject_key_identifier": get_subject_key_identifier(leaf),
        "revocation": revocation,
    }


def main():
    if len(sys.argv) != 5:
        emit(
            {
                "error": "usage",
                "message": (
                    "Usage: ssl_revocation_checker.py "
                    "<path> <host> <port> <gateway>"
                ),
            }
        )
        return 1

    if not 0 < TOTAL_TIMEOUT < HARD_TIMEOUT < 30:
        emit(
            {
                "error": "configuration_error",
                "message": (
                    "timeouts must satisfy "
                    "0 < TOTAL_TIMEOUT < HARD_TIMEOUT < 30"
                ),
            }
        )
        return 1

    signal.signal(signal.SIGALRM, hard_timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, HARD_TIMEOUT)
    total_deadline = Deadline(TOTAL_TIMEOUT)

    path, host, port, gateway = sys.argv[1:5]
    try:
        pem_data = read_certificate_from_zabbix(host, path, port)
        emit(certificate_result(pem_data, gateway, total_deadline))
    except Exception as error:
        emit(
            {
                "error": "certificate_check_error",
                "message": error_text(error),
            }
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
