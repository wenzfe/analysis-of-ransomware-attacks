"""Execution

The adversary is trying to run malicious code.

Execution consists of techniques that result in adversary-controlled 
code running on a local or remote system. 
Techniques that run malicious code are often paired with techniques from all 
other tactics to achieve broader goals, like exploring a network or stealing data. 
For example, an adversary might use a remote access tool to run a 
PowerShell script that does Remote System Discovery.

Mitre: `TA0002 <https://attack.mitre.org/tactics/TA0002/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
