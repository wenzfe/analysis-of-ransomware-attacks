@echo off

@REM Note: change the credentials and the commands to your environment.

@REM set your data
set username=username
set password=password

@REM This script is intended to simplify and shorten the build, upload and un- installation process.
@REM $>package [build | upload | install | remove] packagename

IF "%1" =="build" (
    ECHO "building %2%"
    @REM build the python package (e.g. pkg) on the relative path .\package_pkg\
    py -m build .\package_%2\
) ELSE (
    IF "%1" =="upload" (
        ECHO "uploading %2%"
        py -m twine upload --repository %2% .\package_%2%\dist\*
    ) ELSE (
        IF "%1" =="install" (
            ECHO "installing %2%"
            pip install --index-url https://test.pypi.org/simple/ --no-deps %2%

        ) ELSE (
            IF "%1" =="remove" (
                ECHO "remove %2%"
                pip uninstall %2% -y
            ) ELSE (
                ECHO not found!
            )
        )
    )
)    
