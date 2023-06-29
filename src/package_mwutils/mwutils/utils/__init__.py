"""Utils

A module containing functionalities that are not related and thus not mapped 
to the ATT&CK modules or the other modules in this package.

"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
