@echo off
REM PhishNet Backend Setup Script for Windows

echo.
echo 🚀 PhishNet Backend Setup
echo ==========================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js from https://nodejs.org/
    exit /b 1
)

for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo ✅ Node.js found: %NODE_VERSION%
echo.

REM Install dependencies
echo 📦 Installing dependencies...
call npm install

if %errorlevel% neq 0 (
    echo ❌ Failed to install dependencies
    exit /b 1
)

echo ✅ Dependencies installed successfully
echo.

REM Create .env file if it doesn't exist
if not exist .env (
    echo 📝 Creating .env file from .env.example...
    copy .env.example .env
    echo ✅ .env file created. Please edit it with your configuration.
) else (
    echo ✅ .env file already exists
)

echo.

REM Create necessary directories
echo 📁 Creating necessary directories...
if not exist logs mkdir logs
if not exist models mkdir models

echo ✅ Directories created
echo.

echo 🎉 Setup complete!
echo.
echo Next steps:
echo 1. Edit .env file with your configuration
echo 2. Run 'npm start' to start the server
echo 3. Or run 'npm run dev' for development mode
echo.

pause
