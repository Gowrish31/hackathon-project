# Aegis uninstaller: puts the machine back the way the installer found it.
#   & "C:\Program Files\Aegis\uninstall.ps1"           (elevated PowerShell)
# Also run by the agent itself when the console sends "Remove endpoint" (with -Quiet).
#
#   - stops and deletes the "Aegis Agent" scheduled task
#   - uninstalls Sysmon, but only if Aegis installed it
#   - restores the audit policy backup and the previous PowerShell logging setting
#   - tells the console the endpoint is gone, then deletes C:\Program Files\Aegis

function Uninstall-Aegis([bool]$Quiet) {
  $ErrorActionPreference = 'Continue'
  $Dir = Join-Path $env:ProgramFiles 'Aegis'
  $TaskName = 'Aegis Agent'
  function Say([string]$m) { if (-not $Quiet) { Write-Host "  $m" } }

  $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '  Run this from an Administrator PowerShell.' -ForegroundColor Yellow
    return
  }
  $cfg = $null
  if (Test-Path "$Dir\config.json") { try { $cfg = Get-Content "$Dir\config.json" -Raw | ConvertFrom-Json } catch { } }

  Say 'Stopping the agent'
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
    Where-Object { $_.ExecutablePath -like "$Dir\*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

  if (Get-NetFirewallRule -Group 'Aegis Isolation' -ErrorAction SilentlyContinue) {
    Say 'Lifting network isolation'
    Remove-NetFirewallRule -Group 'Aegis Isolation' -ErrorAction SilentlyContinue
  }

  Say 'Removing ransomware canaries'
  $docs = @("$env:PUBLIC\Documents") + (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'Documents' })
  foreach ($d in $docs) {
    $c = Join-Path $d '!Records'
    if (-not (Test-Path -LiteralPath $c)) { continue }
    # only a folder that holds nothing but our decoys, never someone's own "!Records"
    $ours = 'Accounts-2025.xlsx', 'Contracts-signed.docx', 'Passport-scan.pdf', 'Family-2024.jpg'
    $other = Get-ChildItem -LiteralPath $c -Force | Where-Object { $ours -notcontains $_.Name }
    if (-not $other) { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue }
  }
  Remove-Item -LiteralPath "$env:PUBLIC\Documents\Aegis Ransomware Drill" -Recurse -Force -ErrorAction SilentlyContinue
  # the installer's "My device" shortcut; we may be SYSTEM here, so look on every profile's desktop
  Get-ChildItem -Path "$env:SystemDrive\Users\*\Desktop\Aegis - My device.url", "$env:SystemDrive\Users\*\OneDrive*\Desktop\Aegis - My device.url" -Force -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

  if (Test-Path "$Dir\sysmon\installed-by-aegis.txt") {
    $exe = (Get-Content "$Dir\sysmon\installed-by-aegis.txt" -Raw).Trim()
    Say "Removing Sysmon ($exe)"
    Start-Process -FilePath "$Dir\sysmon\$exe" -ArgumentList '-u', 'force' -Wait -WindowStyle Hidden
  } else {
    Say 'Sysmon was already here before Aegis; leaving it installed'
  }

  if (Test-Path "$Dir\auditpol-backup.csv") {
    Say 'Restoring the previous audit policy'
    Start-Process -FilePath 'auditpol.exe' -ArgumentList '/restore', "/file:`"$Dir\auditpol-backup.csv`"" -Wait -WindowStyle Hidden
  }
  if (Test-Path "$Dir\state.json") {
    $state = Get-Content "$Dir\state.json" -Raw | ConvertFrom-Json
    $sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if ($null -eq $state.script_block_logging) {
      Remove-ItemProperty -Path $sb -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    } else {
      Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value $state.script_block_logging -Type DWord
    }
  }

  if ($cfg -and $cfg.server) {
    try {
      $body = @{ agent_id = $cfg.agent_id } | ConvertTo-Json -Compress
      Invoke-RestMethod -Method Post -Uri "$($cfg.server)/api/enroll/removed" -Body $body -ContentType 'application/json' `
        -Headers @{ 'X-Agent-Token' = $cfg.key; 'X-Agent-Id' = $cfg.agent_id } -TimeoutSec 10 | Out-Null
      Say 'Console notified'
    } catch { Say 'Could not reach the console (it will show the endpoint as offline)' }
  }

  # this script may live inside $Dir, so delete the folder from a separate process a moment later
  Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "timeout /t 3 /nobreak >nul & rmdir /s /q `"$Dir`"" -WindowStyle Hidden
  Say 'Aegis removed.'
}

Uninstall-Aegis ($args -contains '-Quiet')
