#!/bin/sh
# Builds the downloads from public/setup.ps1:
#   public/Aegis-Setup.cmd   batch/PowerShell polyglot: double-click, approve UAC once, the rest runs in one window
#   public/Aegis-Setup.zip   the .cmd zipped (browsers are friendlier to a .zip than a bare .cmd)
# Re-run after editing setup.ps1. The landing page itself has no build step.
set -e
cd "$(dirname "$0")/public"

python3 - <<'EOF'
head = r'''<# :
@echo off
setlocal
title Aegis endpoint setup
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([IO.File]::ReadAllText('%~f0'))"
echo.
pause
exit /b
#>
'''
body = open("setup.ps1", encoding="utf-8").read()
out = (head + body).replace("\r\n", "\n").replace("\n", "\r\n")
open("Aegis-Setup.cmd", "w", encoding="ascii", newline="").write(out)
EOF

rm -f Aegis-Setup.zip
zip -q -X Aegis-Setup.zip Aegis-Setup.cmd
ls -l Aegis-Setup.cmd Aegis-Setup.zip setup.ps1
