"""Utils

A small module that contains a collection of some useful functions.

"""

import logging
from hashlib import sha256
from io import BufferedRandom, BufferedReader, BufferedWriter, BytesIO
from typing import Union

logger = logging.getLogger(__name__)


def sha256_hash(
    data: Union[bytes, BufferedWriter, BufferedReader, BufferedRandom]
) -> str:
    """Get the sha256 hash value of the passed data.

    Args:
        data (Union[bytes, BufferedWriter, BufferedReader, BufferedRandom]): Digested data.

    Raises:
        NotImplementedError: Raised when the data argument is not implemented.

    Returns:
        str: The sha256 hash value.
    """
    # buffer_size is totally arbitrary, change for your app!
    buffer_size = 65536  # lets read stuff in 64kb chunks!
    hashalgo = sha256()
    if isinstance(data, bytes):
        stream = BytesIO(data)
    elif isinstance(data, str):
        stream = BytesIO(data.encode("utf-8"))
    elif isinstance(data, (BufferedWriter, BufferedReader, BufferedRandom)):
        stream = data
    else:
        raise NotImplementedError(
            type(data), "if you try to open a file please use binary mode ('b')"
        )

    while True:
        data = stream.read(buffer_size)
        if not data:
            break
        hashalgo.update(data)
    return hashalgo.hexdigest()
