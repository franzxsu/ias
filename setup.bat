@echo off
setlocal enabledelayedexpansion

echo Starting setup...

:: Step 1: Install Node.js dependencies
echo Installing Node.js dependencies...
CALL npm install




cd ..

echo Setup complete!

echo ```"npm run dev" to start node server

@REM :: Step 2: Set up Python virtual environment
@REM echo Setting up Python virtual environment...
@REM cd flask-api
@REM if not exist "venv" (
@REM     python -m venv venv
@REM     echo Virtual environment created.
@REM ) else (
@REM     echo Virtual environment already exists.
@REM )

@REM :: Activate the virtual environment and install Flask dependencies
@REM call venv\Scripts\activate
@REM echo Installing Flask dependencies...
@REM pip install -r requirements.txt
@REM deactivate