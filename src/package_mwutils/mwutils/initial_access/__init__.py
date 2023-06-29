"""Initial Access

The adversary is trying to get into your network.

Initial Access consists of techniques that use various entry vectors 
to gain their initial foothold within a network. 
Techniques used to gain a foothold include targeted spearphishing and 
exploiting weaknesses on public-facing web servers. 
Footholds gained through initial access may allow for continued access, 
like valid accounts and use of external remote services, or may 
be limited-use due to changing passwords.

Mitre: `TA0001 <https://attack.mitre.org/tactics/TA0001/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
