"""Credential Access

The adversary is trying to steal account names and passwords.

Credential Access consists of techniques for stealing credentials like account names and passwords. 
Techniques used to get credentials include keylogging or credential dumping. 
Using legitimate credentials can give adversaries access to systems, make them 
harder to detect, and provide the opportunity to create more accounts to help achieve their goals.

Mitre: `TA0006 <https://attack.mitre.org/tactics/TA0006/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
