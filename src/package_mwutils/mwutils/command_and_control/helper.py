"""Helper

A module intended to help with communication related tasks.
This module allows to split data into chunks (packets) and also assemble them back together. 
To simplify working with data chunks this module provides uses a Packet dataclass as output.
This matches the MITRE technique `T1030 <https://attack.mitre.org/techniques/T1030/>`_ .

This module also provides functions to decode / encode Base64 in a url-safe way.

.. code:: python

    packets = build_packets("prefix", "This is the message 👋.".encode("utf-8"), 20)
    message = b""
    for packet in packets:
        chunk = unpack_packet(packet)
        print(chunk)
        message += chunk.message_chunk
    print(message.decode("utf-8"))

"""
from base64 import urlsafe_b64decode, urlsafe_b64encode
import binascii
import logging
from dataclasses import dataclass
from io import BufferedRandom, BufferedReader, BufferedWriter, BytesIO
from typing import List, Union

logger = logging.getLogger(__name__)


PACKET_NUMBER_SIZE_IN_BYTES: int = 1
EOF: bytes = "_EOF_".encode("utf-8")
# The delimiter separating prefix and message
PREFIX_DELIMITER: bytes = "::".encode("utf-8")
TYP_SIZE_IN_BYTES: int = 1  # Number of bytes to use for the typ


@dataclass
class Packet:
    """Datastructure for Packets"""

    prefix: str
    typ: str
    number: int
    message_chunk: bytes
    eof: bool


def build_packets(
    prefix: str,
    message: Union[bytes, str, BufferedRandom, BufferedReader, BufferedWriter, BytesIO],
    packet_size: int,
    eof: bytes = EOF,
    packet_number_size_in_bytes: int = PACKET_NUMBER_SIZE_IN_BYTES,
    typ_size_in_bytes: int = TYP_SIZE_IN_BYTES,
    prefix_delimiter: bytes = PREFIX_DELIMITER,
) -> List[bytes]:
    """Converts the message to the packets of the specified size.

    Converts the message into packets of the specified size.
    These (binary) packets have the structure <prefix><typ><ctr><delimiter><message>.
    The typ represents the type of the message.
    The ctr is the counter starting at 0 up to the maximum possible value
    (packet_number_size_in_bytes). When maximal value in the ctr is reached it starts again at 0.


    Args:
        prefix (str): Is included in all packets.
        message (Union[bytes, str, BufferedRandom, BufferedReader, BufferedWriter, BytesIO]):
            The actual data to be used.
        packet_size (int): The number of bytes the packet can have at maximum.
        eof (bytes, optional): The bytes used as a signal for beeing the last package.
            Defaults to EOF.
        packet_number_size_in_bytes (int, optional): The number of bytes used for the counter.
            Defaults to PACKET_NUMBER_SIZE_IN_BYTES.
        typ_size_in_bytes (int, optional): The number of bytes used for the typ.
            Defaults to TYP_SIZE_IN_BYTES.
        prefix_delimiter (bytes, optional): The delimiter separating the header and the message.
            Defaults to PREFIX_DELIMITER.

    Raises:
        NotImplementedError: If the message can't be encoded into a packet.

    Returns:
        List[bytes]: List of packets.
    """

    if isinstance(message, bytes):
        typ = 0
        stream = BytesIO(message)
    elif isinstance(message, str):
        typ = 1
        stream = BytesIO(message.encode("utf-8"))
    elif isinstance(message, (BufferedRandom, BufferedReader, BufferedWriter, BytesIO)):
        typ = 2
        stream = message
    else:
        # Tipp: when implementing a new type
        # 1 byte is used to encode the type of the message
        raise NotImplementedError(typ, "If you try to pass a file use binary mode 'b'")

    encoded_typ = int(typ).to_bytes(typ_size_in_bytes, "big", signed=False)
    ctr = 0
    encoded_prefix = prefix.encode("utf-8")

    result = []
    size = (
        packet_size
        - len(encoded_prefix)
        - len(encoded_typ)
        - packet_number_size_in_bytes
        - len(prefix_delimiter)
    )

    if size < len(eof):
        raise ValueError(
            f"""
            The package size is {packet_size} byte(s): 
            {len(encoded_prefix)} byte(s) for encoded prefix
            {len(encoded_typ)} byte(s) for encoded typ
            {packet_number_size_in_bytes} byte(s) for packet number
            {len(prefix_delimiter)} byte(s) delimiter
            there is no space for the actual message!
            The EOF with {len(eof)} byte(s) must also fit!
            """
        )

    while True:
        # convert counter to bytes
        packet_number = int(ctr % 2 ** (8 * packet_number_size_in_bytes)).to_bytes(
            packet_number_size_in_bytes, "big", signed=False
        )
        # build header
        encoded_header = encoded_prefix + encoded_typ + packet_number + prefix_delimiter
        # get a chunk of data
        chunk = stream.read(size)
        if chunk == b"":  # Send EOF
            result.append(encoded_header + eof)
            break
        # Send data
        result.append(encoded_header + chunk)
        ctr += 1

    return result


def unpack_packet(
    packet: bytes,
    eof: str = EOF,
    prefix_delimiter: bytes = PREFIX_DELIMITER,
    packet_number_size_in_bytes: int = PACKET_NUMBER_SIZE_IN_BYTES,
    typ_size_in_bytes: int = TYP_SIZE_IN_BYTES,
) -> Packet:
    """Convert/decode bytes to a packet dataclass object.

    Note that the prefix can't contain the prefix delimiter!

    Args:
        packet (bytes): The bytes to decode and convert to the package dataclass.
        eof (str, optional): The bytes used as a signal for beeing the last package.
            Defaults to EOF.
        prefix_delimiter (bytes, optional): The delimiter separating the header and the message.
            Defaults to PREFIX_DELIMITER.
        packet_number_size_in_bytes (int, optional): The number of bytes used for the counter.
            Defaults to PACKET_NUMBER_SIZE_IN_BYTES.
        typ_size_in_bytes (int, optional): The number of bytes used for the typ.
            Defaults to TYP_SIZE_IN_BYTES.

    Raises:
        NotImplementedError: If the message contains a unknown typ.

    Returns:
        Packet: The destructed message as a dataclass packet.
    """

    # separate prefix with typ from data
    prefix_typ_ctr, data = packet.split(prefix_delimiter, 1)

    # separate prefix and typ, ctr
    prefix = prefix_typ_ctr[: -(typ_size_in_bytes + packet_number_size_in_bytes)]

    packet_typ = prefix_typ_ctr[
        -(
            typ_size_in_bytes + packet_number_size_in_bytes
        ) : -packet_number_size_in_bytes
    ]
    packet_number = prefix_typ_ctr[-packet_number_size_in_bytes:]

    # convert typ to int
    typ = int.from_bytes(packet_typ, "big", signed=False)

    # separate and convert packet number and data
    packet_number = int.from_bytes(packet_number, "big", signed=False)

    prefix = prefix.decode("utf-8")
    if data == eof:
        data = b""
        eof_flag = True
    else:
        eof_flag = False
    if typ == 0:  # bytes
        typ = bytes
    elif typ == 1:  # str
        typ = str
    elif typ == 2:  # stream
        typ = BytesIO
    else:
        # Tipp: when implementing a new type
        # 1 byte is used to encode the type of the message
        raise NotImplementedError(typ)

    return Packet(
        prefix=prefix, typ=typ, number=packet_number, message_chunk=data, eof=eof_flag
    )


def domainsafe_b64encode(data:bytes) -> str:
    """Encodes the bytes using base64 but removes the padding (= and ==).

    Args:
        data (bytes): The bytes to encode.

    Returns:
        str: The encoded bytes.
    """
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def domainsafe_b64decode(data:str) -> bytes:
    """Base64 decodes a string without the padding (= and ==) to bytes.

    Args:
        data (str): The base64 string.

    Returns:
        bytes: Decoded string.
    """
    try:
        data = urlsafe_b64decode(data)
    except binascii.Error:
        try:
            data = urlsafe_b64decode(data + "=")
        except binascii.Error:
            data = urlsafe_b64decode(data + "==")
    return data
