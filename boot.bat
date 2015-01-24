@echo off

c:\python27\python.exe boot.py

c:\Python27\python.exe python_scripts\usbmux\tcprelay.py -t 22:2222

IF %0 == "%~0"  pause
