@echo off
setlocal
cd /d "%~dp0"
if not exist target\packet-analyzer-1.0.0.jar (
  echo Building project...
  call mvn clean package
  if errorlevel 1 exit /b 1
)
echo === Packet Analyzer: sample packet inspection ===
java -jar target\packet-analyzer-1.0.0.jar show test.pcap -n 10
echo.
echo === Packet Analyzer: analysis ===
java -jar target\packet-analyzer-1.0.0.jar analyze test.pcap -o filtered.pcap -r rules.conf -t 4
pause
