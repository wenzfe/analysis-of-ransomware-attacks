"""Virtualization/Sandbox Evasion

Adversaries may employ various means to detect and avoid virtualization and analysis environments. 
This may include changing behaviors based on the results of checks for the presence of artifacts 
indicative of a virtual machine environment (VME) or sandbox. 
If the adversary detects a VME, they may alter their malware to disengage from the victim 
or conceal the core functions of the implant. 
They may also search for VME artifacts before dropping secondary or additional payloads. 
Adversaries may use the information learned from Virtualization/Sandbox Evasion during 
automated discovery to shape follow-on behaviors.

Adversaries may use several methods to accomplish Virtualization/Sandbox Evasion such as checking 
for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts 
associated with analysis or virtualization. 
Adversaries may also check for legitimate user activity to help determine if it is in an 
analysis environment. 
Additional methods include use of sleep timers or loops within malware code to avoid operating 
within a temporary sandbox.

Mitre: `T1497 <https://attack.mitre.org/techniques/T1497/>`_
"""
import json
import logging
import os
from subprocess import PIPE, STDOUT, run

import dns.resolver as dnsr

logger = logging.getLogger(__name__)


class Sandbox:
    """Methods to detect sandboxing."""

    @staticmethod
    def via_dns() -> float:
        """Checks if a list of domains is resolvable.

        Overrides system default DNS server and use public ones such as 8.8.8.8 or 8.8.4.4.
        Then it checks for the number of records that were resolved.


        Mitre: `T1497.001 <https://attack.mitre.org/versions/v12/techniques/T1497/001/>`_

        Returns:
            float: number of domains that could not be resolved / total number of checked domains
        """
        check_domain = [
            "www.google.com",
            "yahoo.com",
            "microsoft.com",
            "YouTube.com",
            "Facebook.com",
            "Wikipedia.org",
            "Amazon.com",
        ]

        count_unresolved_requests = 0
        count_requests = 0
        dns_resolver = dnsr.Resolver(configure=False)
        dns_resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        try:
            for domain in check_domain:
                try:
                    for ip_address in dns_resolver.resolve(domain):
                        count_requests += 1
                except Exception:
                    logger.info("Could not resolve %s", domain)
                    count_unresolved_requests += 1
        except Exception as ex:
            logger.info(ex)

        return count_unresolved_requests / len(check_domain)


class Virtualization:
    """Methods to detect virtualization"""

    class Linux:
        """Methods to detect if a Linux operation system is virtualized."""

        # https://wiki.tcl-lang.org/page/%2Fdev%2Fdisk#:~:text=On%20Linux%20systems%2C%20%2Fdev%2F,in%20more%20user%2Dfriendly%20names.
        # https://unix.stackexchange.com/questions/89714/easy-way-to-determine-the-virtualization-technology-of-a-linux-machine
        @staticmethod
        def detect_through_dev_disk_by_id() -> bool:
            """Detect Linux virtualization.

            Detect Linux virtualization through (internal or external) disks 
            that are connected to the system under `/dev/disk/by-id`.

            Returns:
                bool: True if virtualization is detected.
                        False if not.
            """
            vms = ["vbox", "qemu"]
            cmd = "ls -l /dev/disk/by-id/ | awk '{ print $9 }' "
            output = os.popen(cmd).read().lower().split("\n")
            for line in output:
                for vm in vms:
                    if vm in line:
                        logger.info("Found virtualization: %s", vm)
                        return True
            logger.info("Found no virtualization")
            return False

        # https://unix.stackexchange.com/questions/89714/easy-way-to-determine-the-virtualization-technology-of-a-linux-machine
        # https://www.freedesktop.org/software/systemd/man/systemd-detect-virt.html
        @staticmethod
        def detect_through_system_detect_virt() -> bool:
            """Detect Linux virtualization.

            Detect Linux virtualization via the `systemd-detect-virt` command.

            Returns:
                bool: True if virtualization is detected.
                        False if not.
            """
            vms = [
                "qemu",
                "kvm",
                "amazon",
                "zvm",
                "vmware",
                "microsoft",
                "oracle",
                "powervm",
                "xen",
                "bochs",
                "uml",
                "parrallels",
                "bhyve",
                "qnx",
                "acrn",
            ]
            cmd = "systemd-detect-virt"
            output = os.popen(cmd).read().replace("\n", "")
            if output in vms:
                logger.info("Found virtualization: %s", output)
                return True
            logger.info("Found no virtualization")
            return False

    class Windows:
        """Methods to detect if a Windows operation system is virtualized."""

        @staticmethod
        def run_powershell(cmd: str) -> str:
            """Methord to execute a powershell command.

            Args:
                cmd (str): The powershell command to run.

            Returns:
                str: The string containing the response of the powershell command.
            """
            completed = run(
                ["powershell", "-Command", cmd], stdout=PIPE, stderr=STDOUT, check=False
            )
            return completed.stdout.decode("utf-8")

        @staticmethod
        def run_powershell_dict(cmd: str) -> dict:
            """Runs the supplied powershell command and returns a dict.

            This is done by appending '| ConvertTo-Json -Compress' and converting
            the output to a dict.

            Args:
                cmd (str): The powershell command to run.

            Returns:
                dict: The dict containing the response of the powershell command.
            """
            return json.loads(
                __class__.run_powershell(cmd + " | ConvertTo-Json -Compress").strip()
            )

        @staticmethod
        def is_virtualized():
            """Detect Windows virtualization.

            Via WMI Objects win32_computersystem and win32_bios.

            Mitre: `T1497.001 <https://attack.mitre.org/versions/v12/techniques/T1497/001/>`_

            Returns:
                bool: True if virtualization is detected.
                        False if not.
            """
            win_computersystem = __class__.run_powershell_dict(
                "Get-WmiObject win32_computersystem | Select-Object Manufacturer, Model"
            )
            win_bios = __class__.run_powershell_dict(
                "Get-WmiObject win32_bios | Select-Object SerialNumber, Version"
            )

            models = ["VirtualBox"]
            if win_computersystem["Model"] in models:
                return True

            manufacturers = ["innotek GmbH", "VMware, Inc."]
            if win_computersystem["Manufacturer"] in manufacturers:
                return True

            serial_numbers = ["0"]
            if win_bios["SerialNumber"] in serial_numbers:
                return True

            return False


if __name__ == "__main__":
    print(f"Probability of sandbox based on resolved DNS records: {Sandbox.via_dns()}")
