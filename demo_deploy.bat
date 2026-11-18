@echo off
title SecFT-Deploy
cd /d D:\29166\Documents\Trae-CN\temp_20261117_03\secft
echo [1/2] 生成 PKI 证书链（根CA / 服务器 / 各用户客户端证书）...
python scripts\gen_certs.py
echo.
echo [2/2] 生成演示用户（PBKDF2 校验值存储，不保存明文口令）...
python scripts\gen_users.py
echo.
echo 部署完成，可以启动服务器了。
pause
