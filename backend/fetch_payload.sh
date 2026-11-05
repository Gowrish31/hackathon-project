#!/bin/sh
# Caches what the one-line installer downloads, so enrolling a laptop needs no internet,
# only a network path to this console. Run once (already done if payload/ has 4 files).
set -e
cd "$(dirname "$0")" && mkdir -p payload && cd payload
PY=3.12.10
curl -fL -o python-embed-amd64.zip https://www.python.org/ftp/python/$PY/python-$PY-embed-amd64.zip
curl -fL -o python-embed-arm64.zip https://www.python.org/ftp/python/$PY/python-$PY-embed-arm64.zip
curl -fL -o Sysmon.zip https://download.sysinternals.com/files/Sysmon.zip
curl -fL -o sysmonconfig.xml https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
ls -la
