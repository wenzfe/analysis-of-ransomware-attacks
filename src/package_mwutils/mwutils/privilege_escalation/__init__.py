"""Privilege Escalation

The adversary is trying to gain higher-level permissions.

Privilege Escalation consists of techniques that adversaries use to 
gain higher-level permissions on a system or network. 
Adversaries can often enter and explore a network with unprivileged access 
but require elevated permissions to follow through on their objectives. 
Common approaches are to take advantage of system weaknesses, misconfigurations, 
and vulnerabilities. Examples of elevated access include:

#. SYSTEM/root level

#. local administrator

#. user account with admin-like access

#. user accounts with access to specific system or perform specific function

These techniques often overlap with Persistence techniques, as OS features that let an 
adversary persist can execute in an elevated context.

Mitre: `TA0004 <https://attack.mitre.org/tactics/TA0004/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
