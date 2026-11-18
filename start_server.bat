@echo off
chcp 65001 >nul
title SecFT 服务器
cd /d "%~dp0"
echo ============================================
echo   SecFT 安全文件传输服务器  (端口 19443/19444)
echo ============================================
echo 首次运行请先执行:
echo   python scripts\gen_certs.py
echo   python scripts\gen_users.py
echo   powershell -ExecutionPolicy Bypass -File scripts\setup_server.ps1
echo ============================================
python run_server.py
pause
