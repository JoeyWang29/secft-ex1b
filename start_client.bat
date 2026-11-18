@echo off
chcp 65001 >nul
title SecFT 客户端
cd /d "%~dp0"
python run_client.py
pause
