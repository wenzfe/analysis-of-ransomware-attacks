"""Reconnaissance

The adversary is trying to gather information they can use to plan future operations.

Reconnaissance consists of techniques that involve adversaries actively or passively 
gathering information that can be used to support targeting. 
Such information may include details of the victim organization, infrastructure, or staff/personnel. 
This information can be leveraged by the adversary to aid in other phases of the 
adversary lifecycle, such as using gathered information to plan and execute 
Initial Access, to scope and prioritize post-compromise objectives, or to drive 
and lead further Reconnaissance efforts.

Mitre: `TA0043 <https://attack.mitre.org/tactics/TA0043/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
