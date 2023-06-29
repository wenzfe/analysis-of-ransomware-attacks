"""System Owner/User Discovery

Adversaries may attempt to identify the primary user, currently logged in user, 
set of users that commonly uses a system, or whether a user is actively using the system. 
They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. 
The information may be collected in a number of different ways using other Discovery techniques, 
because user and username details are prevalent throughout a system and include running 
process ownership, file/directory ownership, session information, and system logs. 
Adversaries may use the information from System Owner/User Discovery during automated discovery 
to shape follow-on behaviors, including whether or not the adversary fully infects the target 
and/or attempts specific actions.

Mitre: `T1033 <https://attack.mitre.org/techniques/T1033/>`_
"""

import ctypes
import logging
import os

logger = logging.getLogger(__name__)


def has_elevated_privileges() -> bool:
    """Check if the program runs with elevated privileges.

    Returns:
        bool: True if the program runs with elevated privileges.
    """
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    logger.info("Running as admin: %s", is_admin)
    return is_admin
