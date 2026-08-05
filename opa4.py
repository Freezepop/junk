#!/usr/bin/python3

import datetime
import socket
import struct
import sys
import zlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend


ZABBIX_TIMEOUT = 5
MAX_RESPONSE_SIZE = 64 * 1024 * 1024

ZBX_PROTOCOL_FLAG = 0x01
ZBX_COMPRESS_FLAG = 0x02
ZBX_LARGE_PACKET_FLAG = 0x04


def recv_exact(sock, length):
    """
    Получает из сокета ровно length байт.
    """
    chunks = []
    received = 0

    while received < length:
        chunk = sock.recv(length - received)

        if not chunk:
            raise ConnectionError(
                "Zabbix Agent closed connection prematurely: "
                "received {} of {} bytes".format(received, length)
            )

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def quote_zabbix_parameter(value):
    """
    Помещает параметр ключа Zabbix в двойные кавычки.

    Подходит для:
      - Linux-путей;
      - Windows-путей;
      - пробелов;
      - кириллицы;
      - запятых и квадратных скобок.

    Обратные слеши Windows-пути не удваиваются.
    """
    if "\x00" in value:
        raise ValueError("File path contains a null byte")

    return '"{}"'.format(
        value.replace('"', '\\"')
    )


def build_zabbix_request(key):
    """
    Формирует запрос Zabbix:

      ZBXD
      flags
      data length: uint32
      reserved: uint32
      payload
    """
    key_bytes = key.encode("UTF-8")

    if len(key_bytes) > 0xFFFFFFFF:
        raise ValueError("Zabbix request is too large")

    header = (
        b"ZBXD"
        + bytes([ZBX_PROTOCOL_FLAG])
        + struct.pack(
            "<II",
            len(key_bytes),
            0
        )
    )

    return header + key_bytes


def receive_zabbix_response(sock):
    """
    Получает и разбирает ответ Zabbix Agent.
    """
    prefix = recv_exact(sock, 5)

    magic = prefix[:4]
    flags = prefix[4]

    if magic != b"ZBXD":
        raise RuntimeError(
            "Invalid Zabbix response header: {!r}".format(magic)
        )

    if not flags & ZBX_PROTOCOL_FLAG:
        raise RuntimeError(
            "Response does not contain Zabbix protocol flag: "
            "0x{:02x}".format(flags)
        )

    if flags & ZBX_LARGE_PACKET_FLAG:
        lengths = recv_exact(sock, 16)

        data_length, reserved_length = struct.unpack(
            "<QQ",
            lengths
        )
    else:
        lengths = recv_exact(sock, 8)

        data_length, reserved_length = struct.unpack(
            "<II",
            lengths
        )

    if data_length > MAX_RESPONSE_SIZE:
        raise RuntimeError(
            "Zabbix Agent response is too large: {} bytes".format(
                data_length
            )
        )

    response = recv_exact(sock, data_length)

    if flags & ZBX_COMPRESS_FLAG:
        try:
            response = zlib.decompress(response)
        except zlib.error as error:
            raise RuntimeError(
                "Cannot decompress Zabbix response: {}".format(error)
            )

        if len(response) > MAX_RESPONSE_SIZE:
            raise RuntimeError(
                "Uncompressed Zabbix response is too large: "
                "{} bytes".format(len(response))
            )

        if (
            reserved_length != 0
            and len(response) != reserved_length
        ):
            raise RuntimeError(
                "Invalid uncompressed response length: "
                "expected {}, received {}".format(
                    reserved_length,
                    len(response)
                )
            )

    if response.startswith(b"ZBX_NOTSUPPORTED"):
        message = response.decode(
            "UTF-8",
            errors="replace"
        ).replace("\x00", ": ").strip()

        raise RuntimeError(message)

    return response


def zabbix_get(host, path, mode, port):
    """
    Получает значение через Zabbix Agent.

    host:
      - DNS;
      - IPv4;
      - IPv6.

    path:
      - Linux;
      - Windows;
      - Unicode/кириллица.
    """
    if mode not in ("exists", "contents"):
        raise ValueError(
            "Unsupported vfs.file mode: {}".format(mode)
        )

    quoted_path = quote_zabbix_parameter(path)

    key = "vfs.file.{}[{}]".format(
        mode,
        quoted_path
    )

    request = build_zabbix_request(key)

    # DNS, IPv4 и IPv6 обрабатываются автоматически.
    # Обратного PTR-запроса здесь нет.
    with socket.create_connection(
        (host, int(port)),
        timeout=ZABBIX_TIMEOUT
    ) as sock:
        sock.settimeout(ZABBIX_TIMEOUT)
        sock.sendall(request)

        return receive_zabbix_response(sock)


def get_certificate_days_left(pem_data):
    """
    Вычисляет количество полных суток до стандартного
    поля notAfter сертификата.

    Расширение 2.5.29.16 не используется.
    """
    cert = x509.load_pem_x509_certificate(
        pem_data,
        default_backend()
    )

    # Новые версии cryptography.
    not_after = getattr(
        cert,
        "not_valid_after_utc",
        None
    )

    # Старые версии cryptography.
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

    now = datetime.datetime.now(
        datetime.timezone.utc
    )

    seconds_left = (
        not_after - now
    ).total_seconds()

    # Такое же округление, как в старом скрипте:
    # неполные сутки отбрасываются.
    return int(seconds_left / 86400)


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: {} <certificate_path> "
            "<host_or_ip> <port>".format(sys.argv[0])
        )
        return 1

    path = sys.argv[1]
    host = sys.argv[2]

    try:
        port = int(sys.argv[3])

        if not 1 <= port <= 65535:
            raise ValueError(
                "Invalid TCP port: {}".format(port)
            )

        exists_response = zabbix_get(
            host=host,
            path=path,
            mode="exists",
            port=port
        )

        exists_value = exists_response.decode(
            "UTF-8",
            errors="replace"
        ).strip("\x00\r\n ")

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

        days_left = get_certificate_days_left(
            pem_data
        )

        print(days_left)
        return 0

    except Exception as error:
        # Для numeric item строка приведёт к Not supported.
        print(
            "ssl_container.py: {}".format(error)
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
