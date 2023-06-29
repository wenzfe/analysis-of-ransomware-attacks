"""File and Directory Discovery

Adversaries may enumerate files and directories or may search in specific locations 
of a host or network share for certain information within a file system. 
Adversaries may use the information from File and Directory Discovery during 
automated discovery to shape follow-on behaviors, including whether or not the 
adversary fully infects the target and/or attempts specific actions.

Many command shell utilities can be used to obtain this information. 
Examples include dir, tree, ls, find, and locate. 
Custom tools may also be used to gather file and directory information 
and interact with the Native API. 
Adversaries may also leverage a Network Device CLI on network devices to 
gather file and directory information (e.g. dir, show flash, and/or nvram).

Mitre: `T1083 <https://attack.mitre.org/techniques/T1083/>`_
"""

import logging
import string
from ctypes import windll
from os import listdir
from os.path import basename
from pathlib import Path
from queue import Queue
from typing import List, Union

logger = logging.getLogger(__name__)


EXCLUDE_DIRS = [
    "Intel",
    "ProgramData",
    "Program Files",
    "Program Files (x86)",
    "Temp",
    "AppData",
    "Local Settings",
    "Temporary Internet Files",
    "WINDOWS",
]


def explore_single_directory(
    src: str,
    fiel_queue: Queue,
    dir_queue: Queue,
    file_type: Union[str, tuple] = "",
    exclude_dirs=EXCLUDE_DIRS,
) -> None:
    """Enummerates the given directory.

    Fills the file and directory queue with the enummerated entries of this directory.

    Args:
        src (str): directory to check.
        fiel_queue (Queue): Queue to add the files.
        dir_queue (Queue): Queue to add the directories.
        file_type (Union[str, tuple], optional): file types that get added to the file_queue.
            Can be a single file extension as a or multiple as a tuble of strings.
            Defaults to `""`.
            Example: `('txt','jpg', 'png')`
        exclude_dirs (List[str], optional): Directorys that don't get added to the dir_queue.
            Defaults to EXCLUDE_DIRS.
    """
    try:
        for entry in Path(src).iterdir():
            if entry.is_file():
                if str(entry).endswith(file_type):
                    fiel_queue.put(entry)
                    logger.debug("Adding %s to fiel_queue", entry)
            elif entry.is_dir():
                if basename(entry) not in exclude_dirs:
                    dir_queue.put(entry)
                    logger.debug("Adding %s to dir_queue", basename(entry))
                else:
                    logger.debug("Not adding %s to dir_queue", basename(entry))
    except PermissionError as ex_permission:
        logger.debug("Permission error: %s", ex_permission)


def explore_directories(
    list_of_dirs: List[str],
    file_type: Union[str, tuple] = "",
    exclude_dirs: List[str] = EXCLUDE_DIRS,
) -> Queue:
    """Enumerate the given directories and visit the directories below.
        Collect all matching files.

    Args:
        list_of_dirs (List[str]): List of directories to initialize the search.
        file_type (Union[str, tuple], optional): file types that get added to the file_queue.
            Can be a single file extension as a or multiple as a tuble of strings.
            Defaults to `""`.
            Example: `('txt','jpg', 'png')`
        exclude_dirs (List[str], optional): Directorys that don't get added to the dir_queue. 
            Defaults to EXCLUDE_DIRS.
    Returns:
        Queue: A queue containing all the files that were found.
    """
    file_queue = Queue()
    directory_queue = Queue()
    for directory in list_of_dirs:
        directory_queue.put(directory)

    while not directory_queue.empty():
        directory = directory_queue.get()
        explore_single_directory(
            directory,
            file_queue,
            directory_queue,
            file_type=file_type,
            exclude_dirs=exclude_dirs,
        )
    return file_queue


def get_drive_letters() -> List[str]:
    """Get a list of all the drive letters of the available storage drives.

    Returns:
        List[str]: List of the windows drive names.
            Example: `['C', 'E', 'F']`
    """

    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1
    logger.info("Windows drive letters: %s", drives)
    return drives


def get_home_directories(drive_letter: str = "C") -> List[str]:
    """Get all windows home directories.

    Args:
        drive_letter (str, optional): Drive to look for user home directories. Defaults to `C`.

    Returns:
        List[str]: ['C:\\Users\\user1']
    """
    users = listdir(f"{drive_letter}:\\Users")

    exclude_directories = [
        "All Users",
        "Default",
        "Default User",
        "desktop.ini",
        "Public",
    ]

    result = []
    for directory in users:
        if directory not in exclude_directories:
            result.append(f"{drive_letter}:\\Users\\{directory}")

    return result
