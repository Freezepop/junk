#!/usr/bin/env python3

"""
Fast, bounded and cryptographically verified certificate revocation check.

The command-line interface is compatible with the previous external check:

    ssl_revocation_checker.py <certificate_path> <agent_host> <agent_port> <gateway>

The certificate is read through the Zabbix agent protocol. AIA/OCSP/CRL HTTP
requests are sent through:

    <gateway>/proxy/<scheme>/<host>/<path>

Exit code 0 is used for every syntactically valid JSON result so that Zabbix
can process "unknown" as data instead of turning the item unsupported.
"""

import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import socket
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    CRLEntryExtensionOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    SignatureAlgorithmOID,
)


warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


# The hard limit remains below the maximum Zabbix external-check timeout.
TOTAL_TIMEOUT = float(os.getenv("SSL_CHECKER_TOTAL_TIMEOUT", "26"))
HARD_TIMEOUT = float(os.getenv("SSL_CHECKER_HARD_TIMEOUT", "28"))

ZABBIX_TIMEOUT = float(os.getenv("SSL_CHECKER_ZABBIX_TIMEOUT", "3"))
ISSUER_TIMEOUT = float(os.getenv("SSL_CHECKER_ISSUER_TIMEOUT", "4"))
OCSP_TIMEOUT = float(os.getenv("SSL_CHECKER_OCSP_TIMEOUT", "5"))
CRL_TIMEOUT = float(os.getenv("SSL_CHECKER_CRL_TIMEOUT", "9"))
MAX_WORKERS = max(1, int(os.getenv("SSL_CHECKER_MAX_WORKERS", "4")))

CACHE_DIR = os.getenv("SSL_CHECKER_CACHE_DIR", "/var/tmp/ssl-checker-cache")
ISSUER_CACHE_TTL = float(os.getenv("SSL_CHECKER_ISSUER_CACHE_TTL", "604800"))
OCSP_CACHE_TTL = float(os.getenv("SSL_CHECKER_OCSP_CACHE_TTL", "300"))
CRL_CACHE_TTL = float(os.getenv("SSL_CHECKER_CRL_CACHE_TTL", "900"))

# Expired local HTTP cache entries are permitted only as transport fallback.
# Their cryptographic thisUpdate/nextUpdate interval is still checked later.
ISSUER_STALE_TTL = float(
    os.getenv("SSL_CHECKER_ISSUER_STALE_TTL", "2592000")
)
OCSP_STALE_TTL = float(os.getenv("SSL_CHECKER_OCSP_STALE_TTL", "86400"))
CRL_STALE_TTL = float(os.getenv("SSL_CHECKER_CRL_STALE_TTL", "604800"))

# A final result is cached no longer than both the signed nextUpdate and this
# cap. The leaf fingerprint is the key, so certificate renewal invalidates it.
STATUS_CACHE_MAX_TTL = float(
    os.getenv("SSL_CHECKER_STATUS_CACHE_MAX_TTL", "3600")
)
STATUS_CACHE_SAFETY = float(
    os.getenv("SSL_CHECKER_STATUS_CACHE_SAFETY", "15")
)

CLOCK_SKEW = float(os.getenv("SSL_CHECKER_CLOCK_SKEW", "300"))
OCSP_WITHOUT_NEXT_UPDATE_MAX_AGE = float(
    os.getenv("SSL_CHECKER_OCSP_MAX_AGE", "3600")
)
CRL_WITHOUT_NEXT_UPDATE_MAX_AGE = float(
    os.getenv("SSL_CHECKER_CRL_MAX_AGE", "86400")
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
MAX_REDIRECTS = int(os.getenv("SSL_CHECKER_MAX_REDIRECTS", "3"))

PEM_CERTIFICATE_RE = re.compile(
    br"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

UTC = datetime.timezone.utc

ALL_CRL_REASONS = {
    x509.ReasonFlags.unspecified,
    x509.ReasonFlags.key_compromise,
    x509.ReasonFlags.ca_compromise,
    x509.ReasonFlags.affiliation_changed,
    x509.ReasonFlags.superseded,
    x509.ReasonFlags.cessation_of_operation,
    x509.ReasonFlags.certificate_hold,
    x509.ReasonFlags.privilege_withdrawn,
    x509.ReasonFlags.aa_compromise,
}


class TotalTimeoutError(TimeoutError):
    pass


class ResponseTooLargeError(RuntimeError):
    pass


class ValidationError(RuntimeError):
    pass


class Deadline:
    def __init__(self, timeout=None, expires_at=None):
        if expires_at is None:
            expires_at = time.monotonic() + float(timeout)
        self.expires_at = expires_at

    def child(self, timeout):
        return Deadline(
            expires_at=min(
                self.expires_at,
                time.monotonic() + float(timeout),
            )
        )

    def remaining(self):
        seconds = self.expires_at - time.monotonic()
        if seconds <= 0:
            raise TotalTimeoutError("operation timeout exceeded")
        return max(0.05, seconds)


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


def error_text(error):
    text = str(error).strip()
    return text if text else error.__class__.__name__


def public_result(value):
    if isinstance(value, dict):
        return {
            key: public_result(item)
            for key, item in value.items()
            if not key.startswith("_")
        }
    if isinstance(value, list):
        return [public_result(item) for item in value]
    if isinstance(value, set):
        return sorted(str(item) for item in value)
    return value


def emit(payload):
    signal.setitimer(signal.ITIMER_REAL, 0)
    sys.stdout.write(json.dumps(public_result(payload), ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


def hard_timeout_handler(_signum, _frame):
    payload = {
        "error": "total_timeout",
        "message": "hard execution deadline exceeded",
        "revocation": {
            "method": "none",
            "status": "unknown",
            "error": "hard execution deadline exceeded",
            "checked_ocsp": [],
            "checked_crl": [],
        },
    }
    encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        os.write(sys.stdout.fileno(), encoded)
    finally:
        os._exit(0)


class FileCache:
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
    def key(method, url, body):
        digest = hashlib.sha256()
        digest.update(method.encode("ascii"))
        digest.update(b"\0")
        digest.update(url.encode("utf-8"))
        digest.update(b"\0")
        if body:
            digest.update(body)
        return digest.hexdigest()

    def paths(self, key):
        return (
            os.path.join(self.directory, key + ".bin"),
            os.path.join(self.directory, key + ".lock"),
        )

    @staticmethod
    def read_with_age(path):
        try:
            age = max(0.0, time.time() - os.path.getmtime(path))
            with open(path, "rb") as cached_file:
                return cached_file.read(), age
        except (FileNotFoundError, OSError):
            return None, None

    @staticmethod
    def acquire_lock(lock_file, deadline):
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

    def write_atomic(self, path, data):
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
            os.replace(temporary_path, path)
            temporary_path = None
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
        body,
        fresh_ttl,
        stale_ttl,
        deadline,
        fetch,
    ):
        if not self.enabled or fresh_ttl <= 0:
            return fetch(), "network"

        key = self.key(method, url, body)
        data_path, lock_path = self.paths(key)
        cached, age = self.read_with_age(data_path)
        if cached is not None and age <= fresh_ttl:
            return cached, "fresh-cache"

        with open(lock_path, "a+b") as lock_file:
            self.acquire_lock(lock_file, deadline)
            cached, age = self.read_with_age(data_path)
            if cached is not None and age <= fresh_ttl:
                return cached, "fresh-cache"

            try:
                downloaded = fetch()
            except Exception:
                if (
                    cached is not None
                    and stale_ttl > 0
                    and age <= stale_ttl
                ):
                    return cached, "stale-cache"
                raise

            self.write_atomic(data_path, downloaded)
            return downloaded, "network"


HTTP_CACHE = FileCache(os.path.join(CACHE_DIR, "http"))
STATUS_CACHE = FileCache(os.path.join(CACHE_DIR, "status"))


def status_cache_path(fingerprint):
    return os.path.join(STATUS_CACHE.directory, fingerprint + ".json")


def read_status_cache(fingerprint):
    if not STATUS_CACHE.enabled:
        return None
    path = status_cache_path(fingerprint)
    try:
        with open(path, "r", encoding="utf-8") as cache_file:
            entry = json.load(cache_file)
        expires_at = float(entry["expires_at"])
        if time.time() + STATUS_CACHE_SAFETY >= expires_at:
            return None
        result = entry["result"]
        if result.get("status") not in ("good", "revoked"):
            return None
        result["cached"] = True
        return result
    except (FileNotFoundError, OSError, ValueError, TypeError, KeyError):
        return None


def write_status_cache(fingerprint, result):
    if not STATUS_CACHE.enabled:
        return
    signed_expiry = result.get("_expires_at")
    if not signed_expiry:
        return
    expires_at = min(
        float(signed_expiry),
        time.time() + STATUS_CACHE_MAX_TTL,
    )
    if expires_at <= time.time() + STATUS_CACHE_SAFETY:
        return
    entry = {
        "expires_at": expires_at,
        "result": public_result(result),
    }
    encoded = json.dumps(
        entry,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    STATUS_CACHE.write_atomic(status_cache_path(fingerprint), encoded)


def recv_exact(sock, size, deadline):
    chunks = []
    received = 0
    while received < size:
        sock.settimeout(deadline.remaining())
        chunk = sock.recv(size - received)
        if not chunk:
            raise ConnectionError(
                "Zabbix connection closed before the full response was read"
            )
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def read_certificate_from_zabbix(host, path, port, deadline):
    operation = deadline.child(ZABBIX_TIMEOUT)
    escaped_path = path.replace("\\", "\\\\").replace('"', '\\"')
    key = 'vfs.file.contents["{}"]'.format(escaped_path)
    key_bytes = key.encode("utf-8")
    request_header = struct.pack("<4sBQ", b"ZBXD", 1, len(key_bytes))

    with socket.create_connection(
        (str(host), int(port)),
        timeout=operation.remaining(),
    ) as sock:
        sock.settimeout(operation.remaining())
        sock.sendall(request_header + key_bytes)
        response_header = recv_exact(sock, 13, operation)
        header, version, length = struct.unpack("<4sBQ", response_header)
        if header != b"ZBXD" or version != 1:
            raise ValidationError("invalid Zabbix response header")
        if length > MAX_CERT_FILE_BYTES:
            raise ResponseTooLargeError(
                "certificate file is larger than {} bytes".format(
                    MAX_CERT_FILE_BYTES
                )
            )
        payload = recv_exact(sock, length, operation)

    if payload.startswith(b"ZBX_NOTSUPPORTED"):
        parts = payload.split(b"\0", 1)
        detail = (
            parts[1].decode("utf-8", "replace")
            if len(parts) == 2
            else "vfs.file.contents is not supported"
        )
        raise ValidationError(detail)
    return payload


def build_gateway_url(target_url, gateway):
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("unsupported URL scheme: " + parsed.scheme)
    if not parsed.netloc:
        raise ValidationError("target URL has no host: " + target_url)
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


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler())


def read_limited_response(response, maximum_bytes, deadline):
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > maximum_bytes:
                raise ResponseTooLargeError(
                    "response is larger than {} bytes".format(maximum_bytes)
                )
        except ValueError:
            pass

    chunks = []
    received = 0
    while True:
        deadline.remaining()
        chunk = response.read(min(65536, maximum_bytes + 1 - received))
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
        if received > maximum_bytes:
            raise ResponseTooLargeError(
                "response is larger than {} bytes".format(maximum_bytes)
            )
    return b"".join(chunks)


def fetch_through_gateway(
    target_url,
    gateway,
    deadline,
    method,
    body,
    headers,
    maximum_bytes,
):
    current_url = target_url
    for redirect_number in range(MAX_REDIRECTS + 1):
        proxy_url = build_gateway_url(current_url, gateway)
        request = urllib.request.Request(
            proxy_url,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with NO_REDIRECT_OPENER.open(
                request,
                timeout=deadline.remaining(),
            ) as response:
                return read_limited_response(
                    response,
                    maximum_bytes,
                    deadline,
                )
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise
            if redirect_number >= MAX_REDIRECTS:
                raise ValidationError("too many HTTP redirects")
            location = error.headers.get("Location")
            if not location:
                raise ValidationError("HTTP redirect has no Location")
            current_url = urllib.parse.urljoin(current_url, location)
    raise ValidationError("too many HTTP redirects")


def gateway_request(
    target_url,
    gateway,
    deadline,
    method="GET",
    body=None,
    content_type=None,
    fresh_ttl=0,
    stale_ttl=0,
    maximum_bytes=MAX_CRL_BYTES,
    operation_timeout=CRL_TIMEOUT,
):
    headers = {"User-Agent": "ssl-revocation-checker/2.0"}
    if content_type:
        headers["Content-Type"] = content_type
    if method == "POST":
        headers["Accept"] = "application/ocsp-response"

    def fetch():
        operation = deadline.child(operation_timeout)
        return fetch_through_gateway(
            target_url,
            gateway,
            operation,
            method,
            body,
            headers,
            maximum_bytes,
        )

    return HTTP_CACHE.get_or_fetch(
        method,
        target_url,
        body,
        fresh_ttl,
        stale_ttl,
        deadline,
        fetch,
    )


def download_issuer(url, gateway, deadline):
    return gateway_request(
        url,
        gateway,
        deadline,
        fresh_ttl=ISSUER_CACHE_TTL,
        stale_ttl=ISSUER_STALE_TTL,
        maximum_bytes=MAX_ISSUER_BYTES,
        operation_timeout=ISSUER_TIMEOUT,
    )


def post_ocsp(url, request_data, gateway, deadline):
    return gateway_request(
        url,
        gateway,
        deadline,
        method="POST",
        body=request_data,
        content_type="application/ocsp-request",
        fresh_ttl=OCSP_CACHE_TTL,
        stale_ttl=OCSP_STALE_TTL,
        maximum_bytes=MAX_OCSP_BYTES,
        operation_timeout=OCSP_TIMEOUT,
    )


def download_crl(url, gateway, deadline):
    return gateway_request(
        url,
        gateway,
        deadline,
        fresh_ttl=CRL_CACHE_TTL,
        stale_ttl=CRL_STALE_TTL,
        maximum_bytes=MAX_CRL_BYTES,
        operation_timeout=CRL_TIMEOUT,
    )


def load_pem_certificates(data):
    certificates = []
    for block in PEM_CERTIFICATE_RE.findall(data):
        certificates.append(
            x509.load_pem_x509_certificate(block, default_backend())
        )
    return certificates


def load_certificates_from_data(data):
    certificates = load_pem_certificates(data)
    if certificates:
        return certificates

    loaders = [
        lambda value: [
            x509.load_der_x509_certificate(value, default_backend())
        ],
        pkcs7.load_der_pkcs7_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    ]
    last_error = None
    for loader in loaders:
        try:
            result = loader(data)
            if result:
                return list(result)
        except (ValueError, TypeError) as error:
            last_error = error
    raise ValidationError(
        "unable to parse certificate data: {}".format(error_text(last_error))
    )


def load_crl_from_data(data):
    try:
        return x509.load_der_x509_crl(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_crl(data, default_backend())


def rsa_padding_for_object(signed_object, hash_algorithm):
    parameters = getattr(
        signed_object,
        "signature_algorithm_parameters",
        None,
    )
    if isinstance(parameters, (padding.PKCS1v15, padding.PSS)):
        return parameters
    algorithm_oid = getattr(signed_object, "signature_algorithm_oid", None)
    if algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
        return padding.PSS(
            mgf=padding.MGF1(hash_algorithm),
            salt_length=hash_algorithm.digest_size,
        )
    return padding.PKCS1v15()


def verify_signature(
    public_key,
    signature,
    signed_data,
    hash_algorithm,
    signed_object=None,
):
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_algorithm is None:
                raise ValidationError("RSA signature has no hash algorithm")
            public_key.verify(
                signature,
                signed_data,
                rsa_padding_for_object(signed_object, hash_algorithm),
                hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_algorithm is None:
                raise ValidationError("ECDSA signature has no hash algorithm")
            public_key.verify(
                signature,
                signed_data,
                ec.ECDSA(hash_algorithm),
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            if hash_algorithm is None:
                raise ValidationError("DSA signature has no hash algorithm")
            public_key.verify(signature, signed_data, hash_algorithm)
        elif isinstance(
            public_key,
            (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
        ):
            public_key.verify(signature, signed_data)
        else:
            raise ValidationError(
                "unsupported public key type: "
                + public_key.__class__.__name__
            )
    except InvalidSignature as error:
        raise ValidationError("invalid cryptographic signature") from error


def certificate_is_issued_by(certificate, issuer):
    if certificate.issuer != issuer.subject:
        return False
    try:
        verify_signature(
            issuer.public_key(),
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_hash_algorithm,
            certificate,
        )
        return True
    except ValidationError:
        return False


def certificate_is_ca(certificate):
    try:
        return certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value.ca
    except x509.ExtensionNotFound:
        return False


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


def get_crl_targets(certificate):
    targets = []
    try:
        points = certificate.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return targets

    for point_number, point in enumerate(points):
        names = []
        if point.full_name:
            for name in point.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    names.append(name.value)

        crl_issuers = []
        if point.crl_issuer:
            for name in point.crl_issuer:
                if isinstance(name, x509.DirectoryName):
                    crl_issuers.append(name.value)

        reasons = (
            set(point.reasons)
            if point.reasons is not None
            else set(ALL_CRL_REASONS)
        )
        for url in names:
            targets.append(
                {
                    "url": url,
                    "point_number": point_number,
                    "point_names": set(names),
                    "crl_issuers": crl_issuers,
                    "reasons": reasons,
                }
            )
    return targets


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


def run_parallel_ordered(tasks):
    if not tasks:
        return []
    results = [None] * len(tasks)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(MAX_WORKERS, len(tasks)),
        thread_name_prefix="ssl-revocation",
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
                results[index] = (False, error_text(error))
    return results


def find_issuer(leaf, local_certificates, issuer_urls, gateway, deadline):
    for candidate in local_certificates:
        if candidate == leaf:
            continue
        if certificate_is_issued_by(leaf, candidate):
            return candidate, "local-chain", []

    if leaf.subject == leaf.issuer and certificate_is_issued_by(leaf, leaf):
        return leaf, "self-signed", []

    checked = []

    def task_for(url):
        def task():
            data, cache_state = download_issuer(url, gateway, deadline)
            candidates = load_certificates_from_data(data)
            for candidate in candidates:
                if certificate_is_issued_by(leaf, candidate):
                    return candidate, cache_state
            raise ValidationError(
                "downloaded object does not contain the leaf issuer"
            )

        return task

    results = run_parallel_ordered([task_for(url) for url in issuer_urls])
    valid = []
    for url, result in zip(issuer_urls, results):
        success, value = result
        if success:
            candidate, cache_state = value
            checked.append(
                {
                    "url": url,
                    "status": "valid",
                    "cache": cache_state,
                    "error": None,
                }
            )
            valid.append((candidate, url))
        else:
            checked.append(
                {
                    "url": url,
                    "status": "invalid",
                    "cache": None,
                    "error": value,
                }
            )

    if valid:
        return valid[0][0], valid[0][1], checked
    return None, None, checked


def der_tlv(data, offset):
    if offset >= len(data):
        raise ValidationError("truncated DER")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValidationError("truncated DER length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValidationError("invalid DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise ValidationError("truncated DER value")
    return tag, offset, end


def ocsp_responder_key_hash(certificate):
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tag, sequence_start, sequence_end = der_tlv(spki, 0)
    if tag != 0x30 or sequence_end != len(spki):
        raise ValidationError("invalid SubjectPublicKeyInfo")
    _algorithm_tag, _algorithm_start, algorithm_end = der_tlv(
        spki,
        sequence_start,
    )
    bit_tag, bit_start, bit_end = der_tlv(spki, algorithm_end)
    if bit_tag != 0x03 or bit_end != sequence_end:
        raise ValidationError("SubjectPublicKeyInfo has no public-key BIT STRING")
    bit_string = spki[bit_start:bit_end]
    if not bit_string or bit_string[0] != 0:
        raise ValidationError("unsupported public-key BIT STRING")
    return hashlib.sha1(bit_string[1:]).digest()


def responder_id_matches(certificate, response):
    responder_name = response.responder_name
    responder_hash = response.responder_key_hash
    if responder_name is not None:
        return certificate.subject == responder_name
    if responder_hash is not None:
        return ocsp_responder_key_hash(certificate) == responder_hash
    return False


def certificate_valid_at(certificate, moment):
    not_before = utc_property(
        certificate,
        "not_valid_before_utc",
        "not_valid_before",
    )
    not_after = utc_property(
        certificate,
        "not_valid_after_utc",
        "not_valid_after",
    )
    return (
        not_before - datetime.timedelta(seconds=CLOCK_SKEW)
        <= moment
        <= not_after + datetime.timedelta(seconds=CLOCK_SKEW)
    )


def delegated_ocsp_signer_is_authorized(signer, issuer, moment):
    if not certificate_is_issued_by(signer, issuer):
        return False
    if not certificate_valid_at(signer, moment):
        return False
    try:
        eku = signer.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        key_usage = signer.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        if not key_usage.digital_signature:
            return False
    except x509.ExtensionNotFound:
        pass
    return True


def verify_ocsp_signature(response, issuer, moment):
    candidates = [issuer]
    candidates.extend(list(getattr(response, "certificates", ())))

    errors = []
    for candidate in candidates:
        try:
            if not responder_id_matches(candidate, response):
                continue
            if candidate != issuer and not delegated_ocsp_signer_is_authorized(
                candidate,
                issuer,
                moment,
            ):
                continue
            verify_signature(
                candidate.public_key(),
                response.signature,
                response.tbs_response_bytes,
                response.signature_hash_algorithm,
                response,
            )
            return candidate
        except Exception as error:
            errors.append(error_text(error))

    detail = "; ".join(errors) if errors else "no authorized responder signer"
    raise ValidationError("OCSP signature validation failed: " + detail)


def validate_ocsp_response(response_data, request, issuer):
    response = ocsp.load_der_ocsp_response(response_data)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValidationError(
            "OCSP responder status: " + str(response.response_status)
        )

    if response.serial_number != request.serial_number:
        raise ValidationError("OCSP serial number does not match the request")
    if response.issuer_name_hash != request.issuer_name_hash:
        raise ValidationError("OCSP issuer name hash does not match")
    if response.issuer_key_hash != request.issuer_key_hash:
        raise ValidationError("OCSP issuer key hash does not match")
    if (
        response.hash_algorithm is None
        or request.hash_algorithm is None
        or response.hash_algorithm.name != request.hash_algorithm.name
    ):
        raise ValidationError("OCSP CertID hash algorithm does not match")

    now = datetime.datetime.now(UTC)
    this_update = utc_property(response, "this_update_utc", "this_update")
    next_update = utc_property(response, "next_update_utc", "next_update")
    produced_at = utc_property(response, "produced_at_utc", "produced_at")

    if this_update is None:
        raise ValidationError("OCSP response has no thisUpdate")
    if this_update > now + datetime.timedelta(seconds=CLOCK_SKEW):
        raise ValidationError("OCSP thisUpdate is in the future")
    if (
        produced_at is not None
        and produced_at > now + datetime.timedelta(seconds=CLOCK_SKEW)
    ):
        raise ValidationError("OCSP producedAt is in the future")

    valid_until = next_update
    if valid_until is None:
        valid_until = this_update + datetime.timedelta(
            seconds=OCSP_WITHOUT_NEXT_UPDATE_MAX_AGE
        )
    if now > valid_until + datetime.timedelta(seconds=CLOCK_SKEW):
        raise ValidationError("OCSP response is expired")

    verify_ocsp_signature(response, issuer, produced_at or now)

    result = {
        "_expires_at": valid_until.timestamp(),
        "revocation_time": None,
        "revocation_reason": None,
    }
    if response.certificate_status == ocsp.OCSPCertStatus.GOOD:
        result["status"] = "good"
    elif response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        result["status"] = "revoked"
        revocation_time = utc_property(
            response,
            "revocation_time_utc",
            "revocation_time",
        )
        result["revocation_time"] = (
            revocation_time.isoformat() if revocation_time else None
        )
        result["revocation_reason"] = (
            str(response.revocation_reason)
            if response.revocation_reason is not None
            else None
        )
    else:
        result["status"] = "unknown"
    return result


def check_one_ocsp(
    leaf,
    issuer,
    issuer_source,
    ocsp_url,
    gateway,
    deadline,
):
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, issuer, hashes.SHA1())
        .build()
    )
    request_data = request.public_bytes(serialization.Encoding.DER)
    response_data, cache_state = post_ocsp(
        ocsp_url,
        request_data,
        gateway,
        deadline,
    )
    result = validate_ocsp_response(response_data, request, issuer)
    result.update(
        {
            "method": "ocsp",
            "ocsp_url": ocsp_url,
            "issuer_url": issuer_source,
            "cache": cache_state,
            "error": None,
        }
    )
    return result


def check_ocsp(
    leaf,
    issuer,
    issuer_source,
    ocsp_urls,
    gateway,
    deadline,
):
    checked = []

    def task_for(url):
        return lambda: check_one_ocsp(
            leaf,
            issuer,
            issuer_source,
            url,
            gateway,
            deadline,
        )

    results = run_parallel_ordered([task_for(url) for url in ocsp_urls])
    valid = []
    for url, result in zip(ocsp_urls, results):
        success, value = result
        if success:
            checked.append(public_result(value))
            valid.append(value)
        else:
            checked.append(
                {
                    "method": "ocsp",
                    "status": "unknown",
                    "ocsp_url": url,
                    "issuer_url": issuer_source,
                    "cache": None,
                    "error": value,
                }
            )

    revoked = next(
        (item for item in valid if item["status"] == "revoked"),
        None,
    )
    if revoked:
        return revoked, checked

    good = next(
        (item for item in valid if item["status"] == "good"),
        None,
    )
    if good:
        return good, checked

    return None, checked


def validate_crl_scope(crl, leaf, issuer, target):
    if crl.issuer != issuer.subject:
        raise ValidationError("CRL issuer does not match certificate issuer")
    verify_signature(
        issuer.public_key(),
        crl.signature,
        crl.tbs_certlist_bytes,
        crl.signature_hash_algorithm,
        crl,
    )

    now = datetime.datetime.now(UTC)
    last_update = utc_property(crl, "last_update_utc", "last_update")
    next_update = utc_property(crl, "next_update_utc", "next_update")
    if last_update is None:
        raise ValidationError("CRL has no lastUpdate")
    if last_update > now + datetime.timedelta(seconds=CLOCK_SKEW):
        raise ValidationError("CRL lastUpdate is in the future")
    valid_until = next_update
    if valid_until is None:
        valid_until = last_update + datetime.timedelta(
            seconds=CRL_WITHOUT_NEXT_UPDATE_MAX_AGE
        )
    if now > valid_until + datetime.timedelta(seconds=CLOCK_SKEW):
        raise ValidationError("CRL is expired")

    coverage = set(target["reasons"])
    indirect = False
    try:
        idp = crl.extensions.get_extension_for_oid(
            ExtensionOID.ISSUING_DISTRIBUTION_POINT
        ).value
        indirect = idp.indirect_crl

        leaf_is_ca = certificate_is_ca(leaf)
        if idp.only_contains_attribute_certs:
            raise ValidationError("CRL contains only attribute certificates")
        if idp.only_contains_ca_certs and not leaf_is_ca:
            raise ValidationError("CRL contains only CA certificates")
        if idp.only_contains_user_certs and leaf_is_ca:
            raise ValidationError("CRL contains only end-entity certificates")

        if idp.full_name:
            idp_names = {
                name.value
                for name in idp.full_name
                if isinstance(name, x509.UniformResourceIdentifier)
            }
            if idp_names and not idp_names.intersection(target["point_names"]):
                raise ValidationError(
                    "CRL issuing distribution point does not match"
                )
        if idp.relative_name is not None:
            raise ValidationError(
                "relative-name CRL distribution point is unsupported"
            )
        if idp.only_some_reasons is not None:
            coverage.intersection_update(set(idp.only_some_reasons))
    except x509.ExtensionNotFound:
        pass

    if indirect:
        raise ValidationError(
            "indirect CRL requires certificateIssuer-aware processing"
        )

    is_delta = False
    try:
        crl.extensions.get_extension_for_oid(ExtensionOID.DELTA_CRL_INDICATOR)
        is_delta = True
    except x509.ExtensionNotFound:
        pass

    return coverage, valid_until, is_delta


def crl_entry_reason(entry):
    try:
        return entry.extensions.get_extension_for_oid(
            CRLEntryExtensionOID.CRL_REASON
        ).value.reason
    except x509.ExtensionNotFound:
        return None


def check_one_crl(leaf, issuer, target, gateway, deadline):
    crl_data, cache_state = download_crl(
        target["url"],
        gateway,
        deadline,
    )
    crl = load_crl_from_data(crl_data)
    coverage, valid_until, is_delta = validate_crl_scope(
        crl,
        leaf,
        issuer,
        target,
    )

    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if entry is not None:
        reason = crl_entry_reason(entry)
        if reason != x509.ReasonFlags.remove_from_crl:
            revocation_date = utc_property(
                entry,
                "revocation_date_utc",
                "revocation_date",
            )
            return {
                "url": target["url"],
                "status": "revoked",
                "cache": cache_state,
                "error": None,
                "revocation_date": (
                    revocation_date.isoformat()
                    if revocation_date
                    else None
                ),
                "revocation_reason": str(reason) if reason else None,
                "_expires_at": valid_until.timestamp(),
                "_coverage": coverage,
            }

    if is_delta:
        raise ValidationError(
            "delta CRL cannot prove good status without its base CRL"
        )

    return {
        "url": target["url"],
        "status": "good",
        "cache": cache_state,
        "error": None,
        "revocation_date": None,
        "revocation_reason": None,
        "_expires_at": valid_until.timestamp(),
        "_coverage": coverage,
    }


def check_crl(leaf, issuer, crl_targets, gateway, deadline):
    checked = []

    def task_for(target):
        return lambda: check_one_crl(
            leaf,
            issuer,
            target,
            gateway,
            deadline,
        )

    results = run_parallel_ordered(
        [task_for(target) for target in crl_targets]
    )
    valid_good = []
    for target, result in zip(crl_targets, results):
        success, value = result
        if success:
            checked.append(public_result(value))
            if value["status"] == "revoked":
                return value, checked
            valid_good.append(value)
        else:
            checked.append(
                {
                    "url": target["url"],
                    "status": "unknown",
                    "cache": None,
                    "error": value,
                    "revocation_date": None,
                    "revocation_reason": None,
                }
            )

    coverage = set()
    expiries = []
    for value in valid_good:
        coverage.update(value["_coverage"])
        expiries.append(value["_expires_at"])

    if coverage.issuperset(ALL_CRL_REASONS):
        return (
            {
                "url": None,
                "status": "good",
                "cache": None,
                "error": None,
                "revocation_date": None,
                "revocation_reason": None,
                "_expires_at": min(expiries),
            },
            checked,
        )
    return None, checked


def base_revocation_result(
    method,
    status,
    checked_ocsp,
    checked_crl,
    source_url=None,
    issuer_url=None,
    revocation_time=None,
    revocation_reason=None,
    error=None,
    expires_at=None,
):
    result = {
        "method": method,
        "status": status,
        "source_url": source_url,
        "issuer_url": issuer_url,
        "revocation_time": revocation_time,
        "revocation_reason": revocation_reason,
        "error": error,
        "checked_ocsp": checked_ocsp,
        "checked_crl": checked_crl,
        "cached": False,
    }
    if expires_at:
        result["_expires_at"] = expires_at
    return result


def check_revocation(
    leaf,
    local_certificates,
    ocsp_urls,
    issuer_urls,
    crl_targets,
    gateway,
    deadline,
):
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    cached = read_status_cache(fingerprint)
    if cached:
        return cached

    issuer, issuer_source, checked_issuers = find_issuer(
        leaf,
        local_certificates,
        issuer_urls,
        gateway,
        deadline,
    )
    if issuer is None:
        result = base_revocation_result(
            "none",
            "unknown",
            [],
            [],
            error="unable to obtain and validate the issuer certificate",
        )
        result["checked_issuers"] = checked_issuers
        return result

    ocsp_result = None
    checked_ocsp = []
    if ocsp_urls:
        ocsp_result, checked_ocsp = check_ocsp(
            leaf,
            issuer,
            issuer_source,
            ocsp_urls,
            gateway,
            deadline,
        )

    if ocsp_result is not None:
        result = base_revocation_result(
            "ocsp",
            ocsp_result["status"],
            checked_ocsp,
            [],
            source_url=ocsp_result["ocsp_url"],
            issuer_url=issuer_source,
            revocation_time=ocsp_result.get("revocation_time"),
            revocation_reason=ocsp_result.get("revocation_reason"),
            expires_at=ocsp_result["_expires_at"],
        )
        result["checked_issuers"] = checked_issuers
        write_status_cache(fingerprint, result)
        return result

    crl_result = None
    checked_crl = []
    if crl_targets:
        crl_result, checked_crl = check_crl(
            leaf,
            issuer,
            crl_targets,
            gateway,
            deadline,
        )

    if crl_result is not None:
        result = base_revocation_result(
            "crl",
            crl_result["status"],
            checked_ocsp,
            checked_crl,
            source_url=crl_result.get("url"),
            issuer_url=issuer_source,
            revocation_time=crl_result.get("revocation_date"),
            revocation_reason=crl_result.get("revocation_reason"),
            expires_at=crl_result["_expires_at"],
        )
        result["checked_issuers"] = checked_issuers
        write_status_cache(fingerprint, result)
        return result

    errors = [
        item.get("error")
        for item in checked_ocsp + checked_crl
        if item.get("error")
    ]
    if not ocsp_urls and not crl_targets:
        errors.append("certificate contains neither OCSP nor CRL URLs")
    elif not crl_targets:
        errors.append("no usable CRL fallback URLs")

    result = base_revocation_result(
        "none",
        "unknown",
        checked_ocsp,
        checked_crl,
        error="; ".join(errors[-3:]) if errors else "no valid response",
    )
    result["checked_issuers"] = checked_issuers
    return result


def certificate_result(pem_data, gateway, deadline):
    certificates = load_certificates_from_data(pem_data)
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
    now = datetime.datetime.now(UTC)
    days_left = math.floor((not_after - now).total_seconds() / 86400)

    ocsp_urls, issuer_urls = get_aia_urls(leaf)
    crl_targets = get_crl_targets(leaf)
    crl_urls = list(dict.fromkeys(target["url"] for target in crl_targets))

    revocation = check_revocation(
        leaf,
        certificates,
        ocsp_urls,
        issuer_urls,
        crl_targets,
        gateway,
        deadline,
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

    if HARD_TIMEOUT >= 30 or TOTAL_TIMEOUT >= HARD_TIMEOUT:
        emit(
            {
                "error": "configuration_error",
                "message": (
                    "timeouts must satisfy "
                    "SSL_CHECKER_TOTAL_TIMEOUT < "
                    "SSL_CHECKER_HARD_TIMEOUT < 30"
                ),
            }
        )
        return 1

    signal.signal(signal.SIGALRM, hard_timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, HARD_TIMEOUT)
    deadline = Deadline(TOTAL_TIMEOUT)

    path, host, port, gateway = sys.argv[1:5]
    try:
        pem_data = read_certificate_from_zabbix(
            host,
            path,
            port,
            deadline,
        )
        emit(certificate_result(pem_data, gateway, deadline))
    except TotalTimeoutError as error:
        emit(
            {
                "error": "total_timeout",
                "message": error_text(error),
                "revocation": {
                    "method": "none",
                    "status": "unknown",
                    "error": error_text(error),
                    "checked_ocsp": [],
                    "checked_crl": [],
                },
            }
        )
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
