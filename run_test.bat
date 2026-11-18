@echo off
chcp 65001 >nul
title SecFT 端到端自动化测试
cd /d "%~dp0"
python scripts\e2e_test.py
pause
