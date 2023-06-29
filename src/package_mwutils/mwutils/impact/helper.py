"""Module to manipulate file extensions.
"""

import logging
from pathlib import Path, PurePath

logger = logging.getLogger(__name__)

FILE_EXTENSION = "encrypted"


def add_extension(file, extension: str = FILE_EXTENSION) -> None:
    """Add a extension to the file.

    Args:
        file: The file to which the extension is added.

        extension (optional): The string, without the dot, to use as a extension.
    """
    target = PurePath(file)
    Path(file).rename(target.with_suffix(target.suffix + f".{extension}"))


def remove_extension(file) -> None:
    """Remove a extension from the given file.

    Args:
        file: The file of which to remove the extension.
    """
    target = PurePath(file)
    Path(file).rename(target.with_suffix(""))
