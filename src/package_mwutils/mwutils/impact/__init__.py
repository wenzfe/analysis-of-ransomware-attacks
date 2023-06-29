"""Impact

The adversary is trying to manipulate, interrupt, or destroy your systems and data.

Impact consists of techniques that adversaries use to disrupt availability or 
compromise integrity by manipulating business and operational processes. 
Techniques used for impact can include destroying or tampering with data. 
In some cases, business processes can look fine, but may have been altered 
to benefit the adversaries’ goals. 
These techniques might be used by adversaries to follow through on their 
end goal or to provide cover for a confidentiality breach.

Mitre: `TA0040 <https://attack.mitre.org/tactics/TA0040/>`_
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
