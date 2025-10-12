@echo off
title 🚨 Smart Incident Reporting System Launcher 🚨
color 0a

echo ===================================================
echo  Starting Smart Incident Reporting System...
echo ===================================================
echo.

REM Start Flask app
start cmd /k "python app.py"
timeout /t 5

REM Start ngrok tunnel
echo Opening ngrok tunnel...
start cmd /k "ngrok http 5000"

echo.
echo ===================================================
echo  ✅ Flask and ngrok are now running!
echo  🌐 Copy your HTTPS link from the ngrok window.
echo ===================================================
pause
