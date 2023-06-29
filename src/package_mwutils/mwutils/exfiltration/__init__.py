"""Exfiltration

The adversary is trying to steal data.

Exfiltration consists of techniques that adversaries may use to steal data from your network. 
Once they’ve collected data, adversaries often package it to avoid detection while removing it. 
This can include compression and encryption. 
Techniques for getting data out of a target network typically include transferring 
it over their command and control channel or an alternate channel and may
 also include putting size limits on the transmission.

Mitre: `TA0007 <https://attack.mitre.org/tactics/TA0007/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
