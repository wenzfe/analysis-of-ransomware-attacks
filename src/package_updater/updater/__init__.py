"""A small package capable of updating itself and packages that use this package as a dependency.
"""
import logging

logging.getLogger(__name__).propagate = False
logging.getLogger(__name__).addHandler(logging.NullHandler())
