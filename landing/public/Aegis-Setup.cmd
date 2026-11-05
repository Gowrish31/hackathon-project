<# :
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
# Aegis setup: connects to the Aegis cloud console (or one on this network) and enrolls this machine.
#
#     irm https://<download site>/setup.ps1 | iex        (or double-click Aegis-Setup.cmd)
#
#   1. Uses the cloud console; if unreachable, looks on the LAN: UDP broadcast on port 47800, then a scan of the local subnet for port 8000.
#   2. Asks it to join. An analyst approves the machine on the dashboard (or the console auto-approves).
#   3. Runs the console's own installer, which reports each step live to the dashboard.
# Nothing is sent anywhere except the console you approve. Override discovery with:
#     $env:AEGIS_CONSOLE = 'http://192.168.1.20:8000'

function Start-AegisSetup {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $Port = if ($env:AEGIS_PORT) { [int]$env:AEGIS_PORT } else { 8000 }
  $CloudConsole = 'https://console.130-210-31-1.sslip.io'
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  function Say([string]$text, [string]$color = 'Gray') { Write-Host "  $text" -ForegroundColor $color }

  function Get-Subnets {
    # IPv4 address + mask + gateways of every interface that is up (no loopback / link-local)
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
      if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback') { continue }
      $props = $nic.GetIPProperties()
      $gws = @($props.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
        ForEach-Object { $_.Address.ToString() })
      foreach ($u in $props.UnicastAddresses) {
        if ($u.Address.AddressFamily -ne 'InterNetwork') { continue }
        $ip = $u.Address.ToString()
        if ($ip -like '127.*' -or $ip -like '169.254.*') { continue }
        $mask = if ($u.IPv4Mask -and $u.IPv4Mask.ToString() -ne '0.0.0.0') { $u.IPv4Mask.GetAddressBytes() } else { [byte[]](255, 255, 255, 0) }
        [pscustomobject]@{ IP = $ip; Bytes = $u.Address.GetAddressBytes(); Mask = $mask; Gateways = $gws }
      }
    }
  }

  function Find-ByBroadcast($subnets) {
    $found = @{}
    $udp = New-Object Net.Sockets.UdpClient 0
    try {
      $udp.EnableBroadcast = $true
      $udp.Client.ReceiveTimeout = 300
      $msg = [Text.Encoding]::ASCII.GetBytes('AEGIS-DISCOVER')
      $targets = @('255.255.255.255')
      foreach ($s in $subnets) {
        $b = for ($i = 0; $i -lt 4; $i++) { $s.Bytes[$i] -bor (255 -bxor $s.Mask[$i]) }
        $targets += ($b -join '.')
      }
      foreach ($t in ($targets | Select-Object -Unique)) { try { [void]$udp.Send($msg, $msg.Length, $t, 47800) } catch { } }
      $until = (Get-Date).AddMilliseconds(1800)
      while ((Get-Date) -lt $until) {
        try {
          $from = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
          $j = [Text.Encoding]::UTF8.GetString($udp.Receive([ref]$from)) | ConvertFrom-Json
          if ($j.aegis -eq 'console' -and $j.url) { $found[$j.url] = $j }
        } catch { }
      }
    } finally { $udp.Close() }
    return $found
  }

  function Find-ByScan($subnets) {
    # every host in each /24 (or smaller) subnet, gateways and .1/.2 first; TCP connect with a short timeout
    $hosts = New-Object Collections.Generic.List[string]
    foreach ($s in $subnets) {
      foreach ($g in $s.Gateways) { $hosts.Add($g) }
      $base = $s.Bytes[0..2] -join '.'
      $lo = 1; $hi = 254
      if ($s.Mask[3] -ne 0) {  # smaller than /24: stay inside it
        $net = $s.Bytes[3] -band $s.Mask[3]; $lo = $net + 1; $hi = $net + (255 -bxor $s.Mask[3]) - 1
      }
      foreach ($n in @(1, 2) + ($lo..$hi)) { if ($n -ge $lo -and $n -le $hi) { $hosts.Add("$base.$n") } }
    }
    $hosts = @($hosts | Select-Object -Unique)
    $open = @()
    for ($i = 0; $i -lt $hosts.Count; $i += 128) {
      $batch = foreach ($h in $hosts[$i..([Math]::Min($i + 127, $hosts.Count - 1))]) {
        $c = New-Object Net.Sockets.TcpClient
        [pscustomobject]@{ Host = $h; Client = $c; Task = $c.ConnectAsync($h, $Port) }
      }
      Start-Sleep -Milliseconds 700
      foreach ($b in $batch) {
        if ($b.Task.Status -eq 'RanToCompletion' -and $b.Client.Connected) { $open += $b.Host }
        try { $b.Client.Close() } catch { }
      }
      if ($open) { break }  # nearest subnet answered; no need to sweep the rest
    }
    $found = @{}
    foreach ($h in $open) {
      try {
        $j = Invoke-RestMethod "http://${h}:$Port/api/discover" -TimeoutSec 3
        if ($j.aegis -eq 'console') { $found["http://${h}:$Port"] = $j }
      } catch { }
    }
    return $found
  }

  function Normalize([string]$addr) {
    $a = $addr.Trim().TrimEnd('/')
    if ($a -notmatch '^https?://') { $a = "http://$a" }
    if ($a -notmatch ':\d+$' -and $a -notmatch '^https://') { $a = "${a}:$Port" }
    return $a
  }

  Write-Host ''
  Write-Host '  AEGIS  endpoint setup' -ForegroundColor Cyan
  Say "$env:COMPUTERNAME, looking for the Aegis console on this network" DarkGray
  Write-Host ''

  # ------------------------------------------------------------------ 1. find the console
  $server = $null
  if ($env:AEGIS_CONSOLE) { $server = Normalize $env:AEGIS_CONSOLE }
  else {
    # the cloud console works from any network; only search the LAN if it cannot be reached
    Write-Host '  Contacting the Aegis cloud console... ' -NoNewline
    try {
      $j = Invoke-RestMethod "$CloudConsole/api/discover" -TimeoutSec 10
      if ($j.aegis -eq 'console') { $server = $CloudConsole; Write-Host 'connected' -ForegroundColor Green }
    } catch { Write-Host 'unreachable' -ForegroundColor DarkGray }
  }
  if (-not $server) {
    $subnets = @(Get-Subnets)
    Write-Host '  Broadcasting for a console...        ' -NoNewline
    $found = Find-ByBroadcast $subnets
    if (-not $found.Count) {
      Write-Host 'no reply' -ForegroundColor DarkGray
      Write-Host "  Scanning the local network (:$Port)... " -NoNewline
      $found = Find-ByScan $subnets
    }
    $list = @($found.Values)
    if ($list.Count -eq 0) {
      Write-Host 'none found' -ForegroundColor Yellow
      Say 'Make sure the console is running and this machine is on the same network.' Yellow
      $typed = Read-Host '  Console address (for example 192.168.1.20:8000), or Enter to quit'
      if (-not $typed) { return }
      $server = Normalize $typed
    } elseif ($list.Count -eq 1) {
      Write-Host 'found' -ForegroundColor Green
      $server = $list[0].url.TrimEnd('/')
      Say "Console: $($list[0].name)  $server" DarkGray
    } else {
      Write-Host "found $($list.Count)" -ForegroundColor Green
      for ($i = 0; $i -lt $list.Count; $i++) { Say ("[{0}] {1}  {2}" -f ($i + 1), $list[$i].name, $list[$i].url) }
      $pick = Read-Host '  Which console? (number)'
      $server = $list[[Math]::Max(0, [int]$pick - 1)].url.TrimEnd('/')
    }
  }

  # ------------------------------------------------------------------ 2. ask to join
  $os = try { ((Get-CimInstance Win32_OperatingSystem).Caption -replace '^Microsoft\s+', '') } catch { 'Windows' }
  $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $body = @{ hostname = $env:COMPUTERNAME; user = "$env:USERDOMAIN\$env:USERNAME"; os = $os; arch = $arch.ToLower() } | ConvertTo-Json -Compress
  try {
    $req = Invoke-RestMethod -Method Post -Uri "$server/api/enroll/request" -Body $body -ContentType 'application/json' -TimeoutSec 10
  } catch {
    Say "Could not reach $server ($($_.Exception.Message))" Red
    return
  }

  Write-Host ''
  if ($req.status -ne 'approved') {
    Say 'Waiting for approval. On the console, open' Yellow
    Write-Host "  Endpoints and approve $env:COMPUTERNAME " -ForegroundColor Yellow -NoNewline
  }
  $until = (Get-Date).AddMinutes(10)
  $st = $null
  while ((Get-Date) -lt $until) {
    try { $st = Invoke-RestMethod "$server/api/enroll/request/$($req.id)" -TimeoutSec 10 }
    catch { Write-Host ''; Say 'The request expired. Run setup again.' Red; return }
    if ($st.status -ne 'pending') { break }
    Write-Host '.' -NoNewline -ForegroundColor DarkGray
    Start-Sleep -Seconds 1
  }
  Write-Host ''
  if ($st.status -eq 'denied') { Say 'The console declined this machine.' Red; return }
  if ($st.status -ne 'approved') { Say 'Nobody approved the request in time. Run setup again.' Red; return }
  Say 'Approved. Starting the installer...' Green

  # ------------------------------------------------------------------ 3. hand over to the console's installer
  $installer = Invoke-RestMethod "$($st.server)/install.ps1?t=$($st.token)" -TimeoutSec 30
  Invoke-Expression $installer
}

Start-AegisSetup
