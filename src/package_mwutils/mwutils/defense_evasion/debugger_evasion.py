"""Debugger Evasion

Adversaries may employ various means to detect and avoid debuggers. 
Debuggers are typically used by defenders to trace and/or analyze the 
execution of potential malware payloads.

Debugger evasion may include changing behaviors based on the results of 
the checks for the presence of artifacts indicative of a debugged environment. 
Similar to Virtualization/Sandbox Evasion, if the adversary detects a debugger, 
they may alter their malware to disengage from the victim or conceal the core 
functions of the implant. 
They may also search for debugger artifacts before dropping secondary or additional payloads.

Mitre: `T1622 <https://attack.mitre.org/techniques/T1622/>`_
"""

import inspect
import logging
import sys
from ctypes import windll

logger = logging.getLogger(__name__)


# https://stackoverflow.com/questions/38634988/check-if-program-runs-in-debug-mode
# https://www.adamsmith.haus/python/answers/how-to-determine-if-code-is-being-run-inside-a-virtual-machine-in-python
def detect_debugger_gettrace() -> bool:
    """Detect debugger via gettrace.

    Returns:
        bool: True if a debugger is detectet. Otherwise False.
    """
    if sys.gettrace():
        logger.info("Found debugger")
        return True
    logger.info("Found no debugger")
    return False


# https://stackoverflow.com/questions/1871549/determine-if-python-is-running-inside-virtualenv
def detect_venv() -> bool:
    """Detect debugger via venv.

    Returns:
        bool: True if a debugger is detectet. Otherwise False.
    """
    if hasattr(sys, "real_prefix"):
        logger.info("Found virtual env")
        return True
    logger.info("Found no virtual env")
    return False


# https://stackoverflow.com/questions/333995/how-to-detect-that-python-code-is-being-executed-through-the-debugger
def detect_debugger_stack() -> bool:
    """Detect debugger via stack.

    Returns:
        bool: True if a debugger is detectet. Otherwise False.
    """
    debuggers = ("pydevd", "pdb")
    for frame in inspect.stack():
        for debugger in debuggers:
            if debugger in frame[1]:
                logger.info("Found debugger: %s", debugger)
                return True
    logger.info("Found no debugger")
    return False


class Windows:
    """Windows specific methods."""

    # https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent
    @staticmethod
    def is_debugger_present() -> bool:
        """Useint the Native Windows API to check if the
        current process is running in the context of the debugger.

        Returns:
            bool: True if a debugger is detectet. Otherwise False.
        """
        found_debugger = windll.kernel32.IsDebuggerPresent() != 0
        logger.info("Detected debugger: %s", found_debugger)
        return found_debugger


if __name__ == "__main__":
    # FORMAT = '[%(asctime)s] [%(funcName)-30s] [%(levelname)-8s] [%(message)s]'
    # logging.basicConfig(filename='malware.log', encoding='utf-8', format=FORMAT, level=0)
    # logging.basicConfig(stream=sys.stdout, format=FORMAT, level=0)

    print(f"is debugger: {detect_debugger_gettrace()}")
    print(f"is debugger: {detect_venv()}")
    print(f"is debugger: {detect_debugger_stack()}")
