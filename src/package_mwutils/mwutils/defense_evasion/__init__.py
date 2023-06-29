"""Defense Evasion

The adversary is trying to avoid being detected.

Defense Evasion consists of techniques that adversaries use to 
avoid detection throughout their compromise. 
Techniques used for defense evasion include uninstalling/disabling 
security software or obfuscating/encrypting data and scripts. 
Adversaries also leverage and abuse trusted processes to hide and 
masquerade their malware. Other tactics’ techniques are cross-listed here 
when those techniques include the added benefit of subverting defenses.

Mitre: `TA0005 <https://attack.mitre.org/tactics/TA0005/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
