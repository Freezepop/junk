#!/usr/bin/python3

import datetime
import socket
import struct
import sys
import warnings

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning


warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning
)

ZABBIX_TIMEOUT = 5
MAX_RESPONSE_SIZE = 10 * 1024 * 1024


def recv_exact(sock, length):
    """
    Получает из сокета ровно указанное количество байт.
    """
    chunks = []
    received = 0

    while received < length:
        chunk = sock.recv(length - received)

        if not chunk:
            raise ConnectionError(
                "Zabbix Agent closed the connection prematurely"
            )

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def zabbix_get(host, path, mode, port):
    """
    Получает значение vfs.file.exists[] или vfs.file.contents[]
    непосредственно от Zabbix Agent.

    host может быть DNS-именем, IPv4 или IPv6.
    PTR-запись не требуется.
    """
    key = "vfs.file.{}[{}]".format(mode, path)
    key_bytes = key.encode("UTF-8")

    request = (
        struct.pack(
            "<4sBQ",
            b"ZBXD",
            1,
            len(key_bytes)
        )
        + key_bytes
    )

    # create_connection самостоятельно разрешает DNS,
    # принимает IPv4/IPv6 и перебирает полученные адреса.
    with socket.create_connection(
        (host, int(port)),
        timeout=ZABBIX_TIMEOUT
    ) as sock:
        sock.settimeout(ZABBIX_TIMEOUT)
        sock.sendall(request)

        response_header = recv_exact(sock, 13)

        magic, version, response_length = struct.unpack(
            "<4sBQ",
            response_header
        )

        if magic != b"ZBXD":
            raise RuntimeError(
                "Invalid Zabbix protocol header: {!r}".format(magic)
            )

        if version != 1:
            raise RuntimeError(
                "Unsupported Zabbix protocol version: {}".format(
                    version
                )
            )

        if response_length > MAX_RESPONSE_SIZE:
            raise RuntimeError(
                "Zabbix Agent response is too large: {} bytes".format(
                    response_length
                )
            )

        response = recv_exact(sock, response_length)

    if response.startswith(b"ZBX_NOTSUPPORTED"):
        error = response.decode(
            "UTF-8",
            errors="replace"
        ).replace("\x00", ": ")

        raise RuntimeError(error)

    return response


def get_certificate_days_left(pem_data):
    """
    Возвращает количество полных суток до стандартного
    поля notAfter сертификата.

    Расширение Private Key Usage Period (2.5.29.16)
    никак не учитывается.
    """
    cert = x509.load_pem_x509_certificate(
        pem_data,
        default_backend()
    )

    # В новых версиях cryptography это timezone-aware поле.
    not_after = getattr(cert, "not_valid_after_utc", None)

    # Совместимость со старыми версиями cryptography.
    if not_after is None:
        not_after = cert.not_valid_after

        if not_after.tzinfo is None:
            not_after = not_after.replace(
                tzinfo=datetime.timezone.utc
            )
        else:
            not_after = not_after.astimezone(
                datetime.timezone.utc
            )

    now = datetime.datetime.now(datetime.timezone.utc)
    seconds_left = (not_after - now).total_seconds()

    # Сохраняем поведение старого скрипта:
    # неполные сутки отбрасываются.
    return int(seconds_left / 86400)


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: {} <certificate_path> <host_or_ip> <port>".format(
                sys.argv[0]
            )
        )
        return 1

    path = sys.argv[1]
    host = sys.argv[2]

    try:
        port = int(sys.argv[3])

        exists_response = zabbix_get(
            host=host,
            path=path,
            mode="exists",
            port=port
        )

        exists_value = exists_response.decode(
            "UTF-8",
            errors="replace"
        ).strip()

        if exists_value == "0":
            raise RuntimeError(
                "Certificate file not found: {}".format(path)
            )

        if exists_value != "1":
            raise RuntimeError(
                "Unexpected vfs.file.exists response: {!r}".format(
                    exists_value
                )
            )

        pem_data = zabbix_get(
            host=host,
            path=path,
            mode="contents",
            port=port
        )

        days_left = get_certificate_days_left(pem_data)
        print(days_left)

        return 0

    except Exception as error:
        # Выводим текст вместо фиктивного числового значения.
        # Для numeric item это приведёт к состоянию Not supported.
        print(
            "ssl_certificate_expiration.py: {}".format(error)
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
