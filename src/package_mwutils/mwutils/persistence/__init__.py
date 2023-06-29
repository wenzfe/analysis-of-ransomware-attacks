"""Persistence

The adversary is trying to maintain their foothold.

Persistence consists of techniques that adversaries use to keep access to 
systems across restarts, changed credentials, and other interruptions 
that could cut off their access. 
Techniques used for persistence include any access, action, or configuration 
changes that let them maintain their foothold on systems, such as replacing or 
hijacking legitimate code or adding startup code.

Mitre: `TA0003 <https://attack.mitre.org/tactics/TA0003/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
