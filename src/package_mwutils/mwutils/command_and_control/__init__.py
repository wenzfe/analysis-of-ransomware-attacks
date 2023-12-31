"""Command and Control

The adversary is trying to communicate with compromised systems to control them.

Command and Control consists of techniques that adversaries may use to communicate 
with systems under their control within a victim network. Adversaries commonly attempt 
to mimic normal, expected traffic to avoid detection. There are many ways an adversary 
can establish command and control with various levels of stealth depending on the 
victim’s network structure and defenses.

Mitre: `TA0011 <https://attack.mitre.org/tactics/TA0011/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
