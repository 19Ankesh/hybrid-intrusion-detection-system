@echo off
echo Stopping Hybrid IDS...
cd /d "%~dp0"
docker-compose down
echo.
echo All services stopped.
pause
