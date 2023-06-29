"""Collection

The adversary is trying to gather data of interest to their goal.

Collection consists of techniques adversaries may use to gather information 
and the sources information is collected from that are relevant to following 
through on the adversary's objectives. 
Frequently, the next goal after collecting data is to steal (exfiltrate) the data. 
Common target sources include various drive types, browsers, audio, video, and email. 
Common collection methods include capturing screenshots and keyboard input.

Mitre: `TA0009 <https://attack.mitre.org/tactics/TA0009/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
