@echo off
setlocal
cd /d "%~dp0"
call mvn test
if errorlevel 1 exit /b 1
if not exist test.pcap (
  echo ERROR: test.pcap is missing.
  exit /b 2
)
if not exist rules.conf (
  echo ERROR: rules.conf is missing.
  exit /b 3
)
if not exist target\packet-analyzer-1.0.0.jar call mvn clean package
java -jar target\packet-analyzer-1.0.0.jar show test.pcap -n 5
java -jar target\packet-analyzer-1.0.0.jar analyze test.pcap -o filtered.pcap -r rules.conf -t 4
if errorlevel 1 exit /b 4
echo ALL TESTS PASSED
pause
