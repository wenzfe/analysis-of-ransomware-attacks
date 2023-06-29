"""Indicator Removal

Adversaries may delete or modify artifacts generated within systems to 
remove evidence of their presence or hinder defenses. 
Various artifacts may be created by an adversary or something that can be 
attributed to an adversary's actions. 
Typically these artifacts are used as defensive indicators related to monitored events, 
such as strings from downloaded files, logs that are generated from user actions, 
and other data analyzed by defenders. 
Location, format, and type of artifact (such as command or login history) 
are often specific to each platform.

Removal of these indicators may interfere with event collection, reporting, 
or other processes used to detect intrusion activity. 
This may compromise the integrity of security solutions by causing notable events to go unreported. 
This activity may also impede forensic analysis and incident response, 
due to lack of sufficient data to determine what occurred.

Mitre: `T1070 <https://attack.mitre.org/techniques/T1070/>`_
"""

import logging
from subprocess import PIPE, STDOUT, run

logger = logging.getLogger(__name__)


def clear_windows_event_logs() -> None:
    """Indicator Removal: Clear Windows Event Logs

    Adversaries may clear Windows Event Logs to hide the activity of an intrusion.
    Windows Event Logs are a record of a computer's alerts and notifications.
    There are three system-defined sources of events: System, Application, and Security,
    with five event types: Error, Warning, Information, Success Audit, and Failure Audit.

    Mitre: `T1070.001 <https://attack.mitre.org/techniques/T1070/001/>`_

    This method clears Windows Event logs via a powershell command.
    Requires admin privileges.
    """

    cmd = "Get-EventLog -LogName * | ForEach {Clear-EventLog $_.log}"

    logger.info("clearing Windows Event Logs")
    run(["powershell", "-Command", cmd], stdout=PIPE, stderr=STDOUT, check=False)
