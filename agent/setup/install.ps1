# Aegis endpoint installer.
#
# The console serves this file with its own address and an enrollment token filled in:
#     irm http://<console>:8000/install.ps1?t=<token> | iex
#
# What it does (each step is reported live to the console's onboarding screen):
#   1. Downloads a private Python runtime (embeddable, no system changes) to C:\Program Files\Aegis
#   2. Enrolls this machine and receives its own agent key
#   3. Installs Sysmon, unless it is already present
#   4. Turns on the Windows audit policies and PowerShell logging the detections need
#      (the previous audit policy is backed up and restored on uninstall)
#   5. Registers the "Aegis Agent" scheduled task (SYSTEM, at startup) and starts it
# Remove everything again with:  & "C:\Program Files\Aegis\uninstall.ps1"

function Install-Aegis {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $Server = '__SERVER__'
  $Token = '__TOKEN__'
  $Dir = Join-Path $env:ProgramFiles 'Aegis'
  $TaskName = 'Aegis Agent'
  $InstallId = [guid]::NewGuid().ToString()
  $Headers = @{ 'X-Enroll-Token' = $Token }

  # ---------------------------------------------------------------- elevation
  $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  Aegis needs Administrator rights. Approve the Windows prompt to continue.' -ForegroundColor Yellow
    $cmd = "irm '$Server/install.ps1?t=$Token' | iex"
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-Command', $cmd)
    return
  }

  # ---------------------------------------------------------------- machine facts
  $arch = 'amd64'
  try {
    if ("$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" -eq 'Arm64') { $arch = 'arm64' }
  } catch {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { $arch = 'arm64' }
  }
  if (-not [Environment]::Is64BitOperatingSystem) { throw '32-bit Windows is not supported.' }
  $osInfo = Get-CimInstance Win32_OperatingSystem
  $osName = ($osInfo.Caption -replace '^Microsoft\s+', '')
  $user = "$env:USERDOMAIN\$env:USERNAME"

  $total = 6
  $script:n = 0
  function Send-Step([string]$step, [string]$state, [string]$detail = '') {
    $body = @{
      install_id = $InstallId; step = $step; state = $state; detail = $detail
      hostname = $env:COMPUTERNAME; user = $user; os = $osName; arch = $arch; os_build = $osInfo.BuildNumber
    } | ConvertTo-Json -Compress
    try {
      Invoke-RestMethod -Method Post -Uri "$Server/api/enroll/progress" -Body $body -ContentType 'application/json' `
        -Headers $Headers -TimeoutSec 10 | Out-Null
    } catch { }
  }
  function Step([string]$step, [string]$label, [scriptblock]$work, [switch]$Optional) {
    $script:n++
    Write-Host ("  [{0}/{1}] {2,-34}" -f $script:n, $total, $label) -NoNewline
    Send-Step $step 'active'
    try {
      $detail = & $work
      if ($detail -is [array]) { $detail = $detail[-1] }
      Write-Host 'ok' -ForegroundColor Green -NoNewline
      if ($detail) { Write-Host "  $detail" -ForegroundColor DarkGray } else { Write-Host '' }
      Send-Step $step 'done' "$detail"
    } catch {
      if ($Optional) {  # not fatal: the agent still collects Security / PowerShell / System logs
        Write-Host 'skipped' -ForegroundColor Yellow
        Write-Host "        $($_.Exception.Message)" -ForegroundColor Yellow
        Send-Step $step 'skip' $_.Exception.Message
        return
      }
      Write-Host 'failed' -ForegroundColor Red
      Write-Host "        $($_.Exception.Message)" -ForegroundColor Red
      Send-Step $step 'fail' $_.Exception.Message
      throw
    }
  }
  function Get-Payload([string]$name, [string]$out) {
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/enroll/payload/$name`?t=$Token" -OutFile $out -TimeoutSec 300
  }
  function Run([string]$exe, [string[]]$argv) {
    $p = Start-Process -FilePath $exe -ArgumentList $argv -Wait -PassThru -WindowStyle Hidden
    return $p.ExitCode
  }

  Write-Host ''
  Write-Host '  AEGIS  endpoint enrollment' -ForegroundColor Cyan
  Write-Host "  $env:COMPUTERNAME  ->  $Server" -ForegroundColor DarkGray
  Write-Host ''

  try {
    # ---------------------------------------------------------- 1. reach the console
    Step 'connect' 'Contacting console' {
      $r = Invoke-RestMethod -Uri "$Server/api/health" -TimeoutSec 10
      if (-not $r.ok) { throw "console at $Server did not answer" }
      "$osName, $arch"
    }

    # ---------------------------------------------------------- 2. runtime
    Step 'runtime' 'Installing agent runtime' {
      if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
          Where-Object { $_.ExecutablePath -like "$Dir\*" } |
          ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
      }
      New-Item -ItemType Directory -Force -Path $Dir, "$Dir\logs" | Out-Null
      $zip = Join-Path $env:TEMP "aegis-python-$arch.zip"
      Get-Payload "python-embed-$arch.zip" $zip
      if (Test-Path "$Dir\python") { Remove-Item "$Dir\python" -Recurse -Force }
      Expand-Archive -Path $zip -DestinationPath "$Dir\python" -Force
      Remove-Item $zip -Force
      Get-Payload 'agent.py' "$Dir\agent.py"
      Get-Payload 'uninstall.ps1' "$Dir\uninstall.ps1"
      "Python 3.12 ($arch), private copy"
    }

    # ---------------------------------------------------------- 3. enroll
    Step 'enroll' 'Enrolling this endpoint' {
      $prev = $null
      if (Test-Path "$Dir\config.json") { try { $prev = Get-Content "$Dir\config.json" -Raw | ConvertFrom-Json } catch { } }
      $body = @{ install_id = $InstallId; hostname = $env:COMPUTERNAME; agent_id = $prev.agent_id } | ConvertTo-Json -Compress
      $r = Invoke-RestMethod -Method Post -Uri "$Server/api/enroll" -Body $body -ContentType 'application/json' -Headers $Headers -TimeoutSec 15
      $cfg = @{ server = $Server; agent_id = $r.agent_id; key = $r.key; install_id = $InstallId; installed_at = (Get-Date).ToUniversalTime().ToString('o') }
      [IO.File]::WriteAllText("$Dir\config.json", ($cfg | ConvertTo-Json))
      # only SYSTEM and Administrators may read the agent key
      icacls "$Dir\config.json" /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
      "agent id $($r.agent_id.Substring(0, 8))"
    }

    # ---------------------------------------------------------- 4. sysmon
    Step 'sysmon' 'Installing Sysmon' {
      $existing = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($existing) { return "already installed ($($existing.Name)), kept its configuration" }
      Get-Payload 'Sysmon.zip' "$Dir\Sysmon.zip"
      Expand-Archive "$Dir\Sysmon.zip" -DestinationPath "$Dir\sysmon" -Force
      Remove-Item "$Dir\Sysmon.zip" -Force
      Get-Payload 'sysmonconfig.xml' "$Dir\sysmon\sysmonconfig.xml"
      $exe = if ($arch -eq 'arm64') { 'Sysmon64a.exe' } else { 'Sysmon64.exe' }
      $code = Run "$Dir\sysmon\$exe" @('-accepteula', '-i', "`"$Dir\sysmon\sysmonconfig.xml`"")
      if ($code -ne 0) { throw "Sysmon install exited with $code" }
      Set-Content -Path "$Dir\sysmon\installed-by-aegis.txt" -Value $exe
      & wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:268435456 | Out-Null
      'driver loaded, SwiftOnSecurity config + LSASS access'
    } -Optional

    # ---------------------------------------------------------- 5. audit policy
    Step 'audit' 'Enabling audit + script logging' {
      if (-not (Test-Path "$Dir\auditpol-backup.csv")) {
        Run 'auditpol.exe' @('/backup', "/file:`"$Dir\auditpol-backup.csv`"") | Out-Null
      }
      $sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
      if (-not (Test-Path "$Dir\state.json")) {
        $before = (Get-ItemProperty -Path $sb -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        [IO.File]::WriteAllText("$Dir\state.json", (@{ script_block_logging = $before } | ConvertTo-Json))
      }
      $policies = @(
        @('Logon', '/success:enable', '/failure:enable'),
        @('Account Lockout', '/success:enable', '/failure:enable'),
        @('Special Logon', '/success:enable'),
        @('User Account Management', '/success:enable', '/failure:enable'),
        @('Security Group Management', '/success:enable'),
        @('Other Object Access Events', '/success:enable'),
        @('Security System Extension', '/success:enable'),
        @('Audit Policy Change', '/success:enable')
      )
      $ok = 0
      foreach ($p in $policies) {
        if ((Run 'auditpol.exe' (@('/set', "/subcategory:`"$($p[0])`"") + $p[1..($p.Count - 1)])) -eq 0) { $ok++ }
      }
      New-Item -Path $sb -Force | Out-Null
      Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value 1 -Type DWord
      "$ok audit categories, PowerShell script blocks"
    }

    # ---------------------------------------------------------- 6. service
    Step 'service' 'Starting the agent service' {
      $action = New-ScheduledTaskAction -Execute "$Dir\python\pythonw.exe" -Argument "`"$Dir\agent.py`" --service" -WorkingDirectory $Dir
      $trigger = New-ScheduledTaskTrigger -AtStartup
      $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
      $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
      Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Aegis endpoint agent: ships security telemetry to the Aegis console.' -Force | Out-Null
      Start-ScheduledTask -TaskName $TaskName
      'runs as SYSTEM, starts with Windows'
    }
  } catch {
    Write-Host ''
    Write-Host '  Enrollment stopped. The console shows which step failed.' -ForegroundColor Red
    return
  }

  # ---------------------------------------------------------- wait for the first heartbeat
  Write-Host ''
  Write-Host '  Waiting for the agent to check in' -NoNewline
  $online = $false
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    Write-Host '.' -NoNewline
    try {
      $s = Invoke-RestMethod -Uri "$Server/api/enroll/installs/$InstallId" -Headers $Headers -TimeoutSec 5
      if ($s.status -eq 'online' -or $s.status -eq 'protected') { $online = $true; break }
    } catch { }
  }
  Write-Host ''
  if ($online) {
    Write-Host ''
    Write-Host "  $env:COMPUTERNAME is protected." -ForegroundColor Green
    Write-Host "  Reporting to $Server" -ForegroundColor DarkGray
  } else {
    Write-Host '  The agent has not checked in yet. Its log is at' -ForegroundColor Yellow
    Write-Host "  $Dir\logs\agent.log" -ForegroundColor Yellow
  }
  Write-Host '  Uninstall any time:' -ForegroundColor DarkGray
  Write-Host "  & `"$Dir\uninstall.ps1`"" -ForegroundColor DarkGray
  Write-Host ''
}

Install-Aegis
