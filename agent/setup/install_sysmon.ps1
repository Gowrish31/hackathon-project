#Requires -RunAsAdministrator
<#
  Prepares a Windows VM for the Aegis agent:
    1. Installs Sysmon (or updates its config) with the SwiftOnSecurity config
    2. Enables the Windows audit policies our detections rely on
    3. Enables PowerShell script block logging
    4. Grows the event logs so nothing rolls over during the demo

  Run in an elevated PowerShell:
    Set-ExecutionPolicy -Scope Process Bypass -Force; .\install_sysmon.ps1
#>
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"
$work = Join-Path $env:ProgramData "AegisSetup"
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host "[1/4] Sysmon" -ForegroundColor Cyan
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
Expand-Archive "$work\Sysmon.zip" -DestinationPath "$work\Sysmon" -Force
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$work\sysmonconfig.xml"
# SwiftOnSecurity logs no ProcessAccess events; we need access to lsass.exe for credential-theft detection
$cfg = Get-Content "$work\sysmonconfig.xml" -Raw
$cfg = $cfg.Replace('<ProcessAccess onmatch="include">', '<ProcessAccess onmatch="include"><TargetImage condition="end with">\lsass.exe</TargetImage>')
Set-Content -Path "$work\sysmonconfig.xml" -Value $cfg -Encoding UTF8

$exe = switch ($env:PROCESSOR_ARCHITECTURE) {
  "ARM64" { "Sysmon64a.exe" }
  "AMD64" { "Sysmon64.exe" }
  default { "Sysmon.exe" }
}
$sysmon = Join-Path "$work\Sysmon" $exe
if (Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue) {
  Write-Host "  Sysmon already installed - updating config"
  & $sysmon -c "$work\sysmonconfig.xml"
} else {
  & $sysmon -accepteula -i "$work\sysmonconfig.xml"
}

Write-Host "[2/4] Audit policies" -ForegroundColor Cyan
$policies = @(
  @("Logon", "/success:enable", "/failure:enable"),
  @("Account Lockout", "/success:enable", "/failure:enable"),
  @("Special Logon", "/success:enable"),
  @("Process Creation", "/success:enable"),
  @("User Account Management", "/success:enable", "/failure:enable"),
  @("Security Group Management", "/success:enable"),
  @("Other Object Access Events", "/success:enable"),   # 4698 scheduled tasks
  @("Security System Extension", "/success:enable"),    # 4697 service install
  @("Audit Policy Change", "/success:enable")
)
foreach ($p in $policies) {
  auditpol /set /subcategory:"$($p[0])" $p[1..($p.Count-1)] | Out-Null
  Write-Host "  enabled: $($p[0])"
}
# include command lines in 4688
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

Write-Host "[3/4] PowerShell script block logging" -ForegroundColor Cyan
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null

Write-Host "[4/4] Log sizes" -ForegroundColor Cyan
wevtutil sl Security /ms:268435456
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600

Write-Host ""
Write-Host "Done. Verify with:  Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5" -ForegroundColor Green
Write-Host "TIP: take a VM snapshot now (name it 'clean-baseline')." -ForegroundColor Yellow
