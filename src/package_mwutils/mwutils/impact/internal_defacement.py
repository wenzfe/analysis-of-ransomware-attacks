"""Defacement: Internal Defacement

An adversary may deface systems internal to an organization in an attempt to 
intimidate or mislead users, thus discrediting the integrity of the systems. 
This may take the form of modifications to internal websites, or directly to 
user systems with the replacement of the desktop wallpaper. 
Disturbing or offensive images may be used as a part of Internal Defacement 
in order to cause user discomfort, or to pressure compliance with accompanying messages. 
Since internally defacing systems exposes an adversary's presence, it often 
takes place after other intrusion goals have been accomplished.

Mitre: `T1491.001 <https://attack.mitre.org/techniques/T1491/001/>`_
"""

import ctypes
import logging

logger = logging.getLogger(__name__)

def change_desktop_background(path:str) -> None:
    """Change the windows desktop background.

    Args:
        path: absolute path to image.
    """
    ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
    logging.info("Changing windows desktop background")
