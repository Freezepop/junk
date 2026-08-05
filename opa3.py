#!/usr/bin/python3

import datetime
import re
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
ERROR_VALUE = "2"
PRIVATE_KEY_USAGE_PERIOD_OID = x509.ObjectIdentifier("2.5.29.16")


def recv_exact(sock, length):
    """
    Получить из сокета ровно length байт.
    """
    chunks = []
    received = 0

    while received < length:
        chunk = sock.recv(length - received)

        if not chunk:
            raise ConnectionError(
                "Zabbix agent closed connection before full response was received"
            )

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def zabbix_get(host, path, mode, port):
    """
    Отправляет запрос к Zabbix Agent по протоколу ZBXD.

    host может быть:
      - DNS-именем;
      - IPv4-адресом;
      - IPv6-адресом.
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

    # create_connection самостоятельно:
    # - распознаёт IP-адрес;
    # - разрешает DNS-имя;
    # - перебирает доступные адреса;
    # - поддерживает IPv4 и IPv6.
    with socket.create_connection(
        (host, int(port)),
        timeout=ZABBIX_TIMEOUT
    ) as sock:
        sock.settimeout(ZABBIX_TIMEOUT)
        sock.sendall(request)

        header = recv_exact(sock, 13)
        magic, version, response_length = struct.unpack(
            "<4sBQ",
            header
        )

        if magic != b"ZBXD":
            raise RuntimeError(
                "Invalid Zabbix response header: {!r}".format(magic)
            )

        if version != 1:
            raise RuntimeError(
                "Unsupported Zabbix protocol version: {}".format(version)
            )

        if response_length > 10 * 1024 * 1024:
            raise RuntimeError(
                "Zabbix response is too large: {} bytes".format(
                    response_length
                )
            )

        response = recv_exact(sock, response_length)

    if response.startswith(b"ZBX_NOTSUPPORTED"):
        message = response.decode("UTF-8", errors="replace")
        raise RuntimeError(
            "Zabbix agent does not support the requested key: {}".format(
                message
            )
        )

    return response


def read_der_length(data, offset):
    """
    Читает DER length начиная с указанного offset.

    Возвращает:
      (длина содержимого, позиция начала содержимого)
    """
    if offset >= len(data):
        raise ValueError("Invalid DER data: missing length")

    first_byte = data[offset]

    if first_byte < 0x80:
        return first_byte, offset + 1

    length_bytes_count = first_byte & 0x7F

    if length_bytes_count == 0:
        raise ValueError("Indefinite DER length is not supported")

    length_end = offset + 1 + length_bytes_count

    if length_end > len(data):
        raise ValueError("Invalid DER data: incomplete length")

    content_length = int.from_bytes(
        data[offset + 1:length_end],
        byteorder="big"
    )

    return content_length, length_end


def parse_generalized_time(value):
    """
    Преобразует GeneralizedTime вида YYYYMMDDHHMMSSZ
    в datetime с часовым поясом UTC.
    """
    match = re.fullmatch(
        r"(\d{14})(?:\.\d+)?Z",
        value
    )

    if not match:
        raise ValueError(
            "Unsupported GeneralizedTime value: {!r}".format(value)
        )

    parsed = datetime.datetime.strptime(
        match.group(1),
        "%Y%m%d%H%M%S"
    )

    return parsed.replace(tzinfo=datetime.timezone.utc)


def get_private_key_not_after(cert):
    """
    Получает notAfter из расширения Private Key Usage Period
    с OID 2.5.29.16.
    """
    extension = cert.extensions.get_extension_for_oid(
        PRIVATE_KEY_USAGE_PERIOD_OID
    ).value

    # В новых версиях cryptography это расширение может
    # поддерживаться как отдельный объект.
    not_after = getattr(extension, "not_after", None)

    if not_after is not None:
        if not_after.tzinfo is None:
            not_after = not_after.replace(
                tzinfo=datetime.timezone.utc
            )

        return not_after.astimezone(datetime.timezone.utc)

    # В старых версиях cryptography расширение возвращается
    # как UnrecognizedExtension, а DER лежит в поле value.
    raw_value = getattr(extension, "value", None)

    if not isinstance(raw_value, bytes):
        raise ValueError(
            "Cannot read Private Key Usage Period extension"
        )

    # Структура расширения:
    #
    # PrivateKeyUsagePeriod ::= SEQUENCE {
    #     notBefore [0] GeneralizedTime OPTIONAL,
    #     notAfter  [1] GeneralizedTime OPTIONAL
    # }
    #
    # DER-тег [1] — 0x81.
    tag_position = raw_value.find(b"\x81")

    if tag_position == -1:
        raise ValueError(
            "Private Key Usage Period does not contain notAfter"
        )

    content_length, content_start = read_der_length(
        raw_value,
        tag_position + 1
    )

    content_end = content_start + content_length

    if content_end > len(raw_value):
        raise ValueError(
            "Invalid Private Key Usage Period DER data"
        )

    generalized_time = raw_value[
        content_start:content_end
    ].decode("ASCII")

    return parse_generalized_time(generalized_time)


def get_days_left(pem_data):
    """
    Загружает сертификат и возвращает количество суток
    до notAfter расширения Private Key Usage Period.
    """
    cert = x509.load_pem_x509_certificate(
        pem_data,
        default_backend()
    )

    not_after = get_private_key_not_after(cert)
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
            ),
            file=sys.stderr
        )
        print(ERROR_VALUE)
        return 0

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
            print("Certificate file not found!")
            return 0

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

        days_left = get_days_left(pem_data)
        print(days_left)

    except (
        socket.timeout,
        TimeoutError,
        ConnectionRefusedError,
        ConnectionResetError,
        ConnectionError,
        socket.gaierror,
        OSError,
        RuntimeError,
        ValueError,
        x509.ExtensionNotFound
    ) as error:
        # В stdout отдаём только значение для Zabbix.
        print(ERROR_VALUE)

        # Подробность остаётся в stderr и не портит числовой результат.
        print(
            "ssl_container_extension.py: {}".format(error),
            file=sys.stderr
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
