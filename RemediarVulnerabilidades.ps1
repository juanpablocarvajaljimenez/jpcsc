reg delete  HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /f
reg delete  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUServer /f
reg delete  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUStatusServer /f
C:\Windows\SysWOW64\regsvr32 /u /s msxml4.dll
regsvr32 /u /s msxml4.dll
del /f C:\Windows\SysWOW64\msxml4.dll
del /f C:\Windows\SysWOW64\msxml4.inf
del /f C:\Windows\SysWOW64\msxml4a.dll
del /f C:\Windows\SysWOW64\msxml4r.dll
powershell "Stop-Service -Name Spooler -Force"
powershell "Set-Service -Name Spooler -StartupType Disabled"
powershell "Rename-LocalUser -Name "Guest" -NewName "INV""
icacls %windir%\system32\config\*.* /inheritance:e
REG ADD HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
REG ADD HKU\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
REG ADD HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v "RestrictNullSessAccess" /t REG_DWORD /d "1" /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters  /v "EnableSecuritySignature" /t REG_DWORD /d "1" /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters  /v "RequireSecuritySignature" /t REG_DWORD /d "1" /f
REG ADD HKLM\System\CurrentControlSet\Services\LanManServer\Parameters  /v "EnableSecuritySignature" /t REG_DWORD /d "1" /f
REG ADD HKLM\System\CurrentControlSet\Services\LanManServer\Parameters  /v "RequireSecuritySignature" /t REG_DWORD /d "1" /f
REG ADD HKLM\System\CurrentControlSet\Control\LSA /v "RestrictAnonymous" /t REG_DWORD /d "2" /f
REG ADD "HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_SZ /d "0" /f
REG ADD HKLM\SOFTWARE\policies\microsoft\office\16.0\common\officeupdate /v "enableautomaticupdates" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 72 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
REG ADD HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters /v "IPEnableRouter" /t REG_DWORD /d "0" /f
REG ADD HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\FileSystem /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
REG ADD HKLM\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability /v "ScanOnDemand" /t REG_DWORD /d "1" /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability /v "ScanOnDemand" /t REG_DWORD /d "1" /f
REG ADD HKLM\SOFTWARE\Qualys\QualysAgent\ScanOnDemand\Vulnerability /v "ScanOnDemand" /t REG_DWORD /d "1" /f
setx /M LOG4J_FORMAT_MSG_NO_LOOKUPS "true"
net stop wuauserv
net start wuauserv
net start gupdate
net start gupdatem
Wuauclt.exe /detectnow
Wuauclt.exe /reportnow /detectnow
Wuauclt.exe /force
wuauclt.exe /detectnow /updatenow
control wuaucpl.cpl
UsoClient RestartDevice
UsoClient StartScan
UsoClient StartDownload
UsoClient StartInstall
net user IT PassContIT1% /add 
net localgroup administrators jp /add 
net localgroup administrators ecopetrol\c101539y /add 
install-module PSWindowsUpdate -force
Install-WindowsUpdate -AcceptAll -AutoReboot
hostname
