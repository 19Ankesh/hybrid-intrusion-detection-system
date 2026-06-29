@echo off
echo Starting Hybrid IDS...
cd /d "%~dp0"
docker-compose up -d
echo.
echo All services started!
echo.
echo Dashboard  : http://localhost:3000
echo Backend API: http://localhost:8000/docs
echo Health Check: http://localhost:8000/health
echo.
start http://localhost:3000
echo Press any key to close this window...
pause > nul
