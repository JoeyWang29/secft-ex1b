@echo off
title SecFT-Deploy
cd /d D:\29166\Documents\Trae-CN\temp_20261117_03\secft
echo [1/2] Generate PKI certificate chain (root CA / server / client certs) ...
python scripts\gen_certs.py
echo.
echo [2/2] Generate demo users (PBKDF2 verifiers, no plaintext passwords) ...
python scripts\gen_users.py
echo.
echo Deployment done. You can start the server now.
pause
