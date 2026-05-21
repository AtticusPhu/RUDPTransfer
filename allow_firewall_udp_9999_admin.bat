@echo off
netsh advfirewall firewall add rule name="RUDP Transfer UDP 9999" dir=in action=allow protocol=UDP localport=9999
netsh advfirewall firewall add rule name="RUDP Discovery UDP 9998" dir=in action=allow protocol=UDP localport=9998
pause
