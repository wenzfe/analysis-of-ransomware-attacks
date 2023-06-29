"""A Module to interact with zip files. 

You can create them, add files to them and list its contents.

"""


import logging
from typing import List
from zipfile import ZipFile

logger = logging.getLogger(__name__)


def write_file_to_zip(zip_name: str, filename: str, data) -> None:
    """Write the file into the archive, Its contents is the data.
    You can also create a (empty) directory by adding a trailing slash (/)
    If no filename is given, a empty archive is created.

    Example:
       write_file_to_zip("my.zip","a.txt", "some data")

    Args:
        zip_name (str): The name of the archive.
        filename (str): The name of the file in the archive.
            `sub/file.txt` creates a file in a directory.
        data (_type_): The data inside the file.
    """
    with ZipFile(zip_name, "a") as zipfile:
        zipfile.writestr(filename, data)


def list_zip_contents(zip_name: str) -> List[str]:
    """List the contents of the archive.

    Args:
        zip_name (str): The name of the archive.

    Returns:
        List[str]: List of filenames (full path) inside the archive.
    """
    with ZipFile(zip_name, "r") as zipfile:
        return zipfile.namelist()


def read_file_from_zip(zip_name: str, filename: str) -> bytes:
    """Read a file inside the specified zip archive.

    Args:
        zip_name (str): The name of the archive.
        filename (str): The name of the file inside tha archive to read from.

    Returns:
        bytes: The file content in bytes.
    """
    with ZipFile(zip_name, "r") as zipfile:
        return zipfile.read(filename)


def get_toc_of_zip(zip_name: str) -> str:
    """Get the table of contents for the zip file.

    Args:
        zip_name (str): The zip archive.

    Returns:
        str: The TOC.
    """
    with ZipFile(zip_name, "r") as zipfile:
        table = f"{'File name':<50} {'File size (bytes)':>20}"
        for line in zipfile.infolist():
            table += f"\n{line.filename:<50} {line.file_size:>20}"
        return table
