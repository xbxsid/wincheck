# WinLite Security / CIS-lite Check + OS/Disk/SMART/Restore Storage -> n8n (no HMAC)
# Windows PowerShell 5.1+ (Run as Administrator recommended)

[CmdletBinding()]
param(
  [string]$WebhookUrl,
  [string]$ReportBase     = "$(Join-Path $env:ProgramData 'CG\LiteCheck\Windows_Lite_Check')",
  [int]$HttpTimeoutSec    = 30,
  [int]$RetryCount        = 0,
  [int]$RetryDelaySec     = 3,
  [int]$MinFreePercent    = 15,
  [switch]$OnlySendNonCompliant,   # if set, send only rows with status "No"
  [switch]$FailOnNonCompliant      # if set, exit non-zero if any "No"
)

$ErrorActionPreference = 'SilentlyContinue'

# ----------------------------
# Paths / output
# ----------------------------
$OutDir   = Split-Path $ReportBase -Parent
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
$CsvPath  = "$ReportBase.csv"
$QueueDir = Join-Path $OutDir "outbox"
if (-not (Test-Path $QueueDir)) { New-Item -Path $QueueDir -ItemType Directory -Force | Out-Null }

# ----------------------------
# Helpers
# ----------------------------
function Add-Row {
  param(
    [string]$Item,
    [string]$Status,
    [string]$Detail
  )
  if (-not $script:Rows) {
    $script:Rows = New-Object System.Collections.Generic.List[psobject]
  }
  $script:Rows.Add([pscustomobject]@{
    time   = (Get-Date).ToUniversalTime().ToString("o")
    device = $env:COMPUTERNAME
    user   = $env:USERNAME
    item   = $Item
    status = $Status
    detail = $Detail
  }) | Out-Null
}

function YesNo {
  param([bool]$Value)
  if ($Value) { "Yes" } else { "No" }
}

function Send-ToN8N {
  param(
    [string]$Url,
    [object]$Rows,
    [int]$TimeoutSec,
    [int]$Retries,
    [int]$DelaySec
  )

  if (-not $Url) {
    Write-Warning "WebhookUrl empty. Skipping POST."
    return $false
  }

  $payload = @{ rows = $Rows } | ConvertTo-Json -Depth 6

  for ($i=0; $i -le $Retries; $i++) {
    try {
      Invoke-RestMethod -Uri $Url -Method Post `
        -Headers @{ "Content-Type" = "application/json" } `
        -Body $payload -TimeoutSec $TimeoutSec | Out-Null
      Write-Host "Sent results to n8n ($Url)"
      return $true
    }
    catch {
      Write-Warning ("POST attempt {0} failed: {1}" -f ($i + 1), $_.Exception.Message)
      if ($i -lt $Retries) { Start-Sleep -Seconds $DelaySec }
    }
  }

  # queue to disk
  $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $qPath = Join-Path $QueueDir ("winlite_{0}_{1}.json" -f $env:COMPUTERNAME, $ts)
  $payload | Out-File -FilePath $qPath -Encoding UTF8
  Write-Warning ("Queued payload for retry: {0}" -f $qPath)
  return $false
}

function Format-Bytes {
  param([ulong]$Bytes)
  if ($Bytes -ge 1PB) { return ("{0:N2} PB" -f ($Bytes / 1PB)) }
  if ($Bytes -ge 1TB) { return ("{0:N2} TB" -f ($Bytes / 1TB)) }
  if ($Bytes -ge 1GB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
  if ($Bytes -ge 1MB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
  if ($Bytes -ge 1KB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
  return ("{0} B" -f $Bytes)
}
Set-Variable -Name KB -Value 1KB -Option Constant
Set-Variable -Name MB -Value 1MB -Option Constant
Set-Variable -Name GB -Value 1GB -Option Constant
Set-Variable -Name TB -Value 1TB -Option Constant
Set-Variable -Name PB -Value 1PB -Option Constant

function Test-Cmd {
  param([string]$Name)
  try {
    Get-Command -Name $Name -ErrorAction Stop | Out-Null
    return $true
  } catch {
    return $false
  }
}

# ============================
# OS INFO
# ============================
try {
  $cv  = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
  $os  = Get-CimInstance Win32_OperatingSystem
  $ubr = $cv.UBR
  $dispVer = $cv.DisplayVersion
  $prod = $cv.ProductName
  $ver  = $cv.ReleaseId
  $build = $cv.CurrentBuild
  $arch = $os.OSArchitecture

  $inst = ""
  if ($os.InstallDate) {
    $inst = ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)).ToString("yyyy-MM-dd")
  }

  $lbt = ""
  if ($os.LastBootUpTime) {
    $lbt = ([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)).ToString("yyyy-MM-dd HH:mm")
  }

  $detail = "Product=$prod; DisplayVersion=$dispVer; Version=$ver; Build=$build.$ubr; Arch=$arch; Installed=$inst; LastBoot=$lbt"
  Add-Row "OS info" "Info" $detail
}
catch {
  Add-Row "OS info" "Unknown" "Unable to query OS details"
}

# ============================
# ACCOUNTS / CIS-ish
# ============================

# Current user local admin?
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  $isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  $status = "No"
  if ($isAdmin) { $status = "Yes" }

  Add-Row "Current user in Local Administrators" $status $id.Name
}
catch {
  Add-Row "Current user in Local Administrators" "Unknown" "Check failed"
}

# Local Administrators group members
try {
  $admins = $null

  if (Test-Cmd "Get-LocalGroupMember") {
    $admins = (Get-LocalGroupMember -Group "Administrators" |
      Select-Object -ExpandProperty Name) -join "; "
  }

  if (-not $admins) {
    $raw = (& net localgroup administrators) 2>$null
    if ($raw) {
      $list = $raw |
        Select-Object -SkipWhile { $_ -notmatch '^-+$' } |
        Select-Object -Skip 1 |
        Where-Object { $_ -and ($_ -notmatch 'The command completed successfully') -and ($_ -notmatch '^-+$') }
      $admins = ($list -join '; ').Trim()
    }
  }

  if (-not $admins) { $admins = "(none or access denied)" }
  Add-Row "Local Administrators group members" "Info" $admins
}
catch {
  Add-Row "Local Administrators group members" "Unknown" "Get-LocalGroupMember/net failed"
}

# Built-in Administrator disabled (SID -500)
try {
  $adminName = $null
  $disabled  = $null

  if (Test-Cmd "Get-LocalUser") {
    $lu = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like '*-500' }
    if ($lu) {
      $adminName = $lu.Name
      $disabled  = (-not $lu.Enabled)
    }
  }

  if (-not $adminName) {
    $ua = wmic useraccount where "sid like '%-500'" get name,disabled /value 2>$null
    if ($ua) {
      $lines = $ua | Where-Object { $_ -match '=' }
      foreach ($l in $lines) {
        $p = $l -split '=', 2
        if ($p[0] -eq 'Name')     { $adminName = $p[1].Trim() }
        if ($p[0] -eq 'Disabled') { $disabled  = ($p[1].Trim() -eq 'TRUE') }
      }
    }
  }

  if ($adminName) {
    $status = YesNo $disabled
    $detail = "Name=$adminName; Disabled=$disabled"
    Add-Row "Built-in Administrator disabled" $status $detail
  }
  else {
    Add-Row "Built-in Administrator disabled" "Unknown" "Could not determine -500 account"
  }
}
catch {
  Add-Row "Built-in Administrator disabled" "Unknown" "Query failed"
}

# Guest account disabled
try {
  $guestName = $null
  $guestDisabled = $null

  if (Test-Cmd "Get-LocalUser") {
    $g = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($g) {
      $guestName = $g.Name
      $guestDisabled = (-not $g.Enabled)
    }
  }

  if ($guestName) {
    $status = YesNo $guestDisabled
    $detail = "Disabled=$guestDisabled"
    Add-Row "Guest account disabled" $status $detail
  }
  else {
    Add-Row "Guest account disabled" "Unknown" "Guest account missing or Get-LocalUser unavailable"
  }
}
catch {
  Add-Row "Guest account disabled" "Unknown" "Query failed"
}

# Password / lockout policy (summary)
try {
  $netOut = net accounts 2>$null
  if ($netOut) {
    $map = @{}
    foreach ($line in $netOut) {
      if ($line -match '^\s*(.+?)\s{2,}(.+)$') {
        $k = $matches[1].Trim()
        $v = $matches[2].Trim()
        $map[$k] = $v
      }
    }

    $minLen   = $map['Minimum password length']
    $maxAge   = $map['Maximum password age (days)']
    $minAge   = $map['Minimum password age (days)']
    $hist     = $map['Length of password history maintained']
    $lockTh   = $map['Lockout threshold']
    $lockDur  = $map['Lockout duration (minutes)']
    $obsWin   = $map['Lockout observation window (minutes)']

    $detail = "MinLength=$minLen; MaxAgeDays=$maxAge; MinAgeDays=$minAge; History=$hist; LockoutThreshold=$lockTh; LockoutDuration=$lockDur; LockoutWindow=$obsWin"
    Add-Row "Password/lockout policy (summary)" "Info" $detail
  }
  else {
    Add-Row "Password/lockout policy (summary)" "Unknown" "net accounts returned no data"
  }
}
catch {
  Add-Row "Password/lockout policy (summary)" "Unknown" "Query failed"
}

# ============================
# NETWORK / SERVICES
# ============================

# Windows File Sharing (SMB server)
try {
  $serverSvc = Get-Service -Name "LanmanServer" -ErrorAction Stop
  $svcState  = $serverSvc.Status.ToString()
  $fwRules   = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue |
               Where-Object { $_.Enabled -eq 'True' }

  if ($fwRules) {
    $profiles = $fwRules | Select-Object -ExpandProperty Profile | Sort-Object -Unique
    $fwState = "Enabled (" + ($profiles -join ",") + ")"
  }
  else {
    $fwState = "Disabled"
  }

  $status = "Off"
  if ($serverSvc.Status -eq 'Running') { $status = "On" }

  $detail = "Server service: $svcState; Firewall: $fwState"
  Add-Row "Windows File Sharing (SMB server)" $status $detail
}
catch {
  Add-Row "Windows File Sharing (SMB server)" "Unknown" "Query failed"
}

# SMBv1 disabled
try {
  $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
  $status = "No"
  if ($feat.State -eq 'Disabled') { $status = "Yes" }
  $detail = "State=" + $feat.State
  Add-Row "SMBv1 disabled" $status $detail
}
catch {
  Add-Row "SMBv1 disabled" "Unknown" "Get-WindowsOptionalFeature failed"
}

# Firewall profiles
try {
  $profiles = Get-NetFirewallProfile
  $enabledProfiles = $profiles | Where-Object { $_.Enabled -eq 'True' }
  $allOn = ($enabledProfiles.Count -eq $profiles.Count)

  $status = "No"
  if ($allOn) { $status = "Yes" }

  $detailParts = @()
  foreach ($p in $profiles) {
    $detailParts += ($p.Name + "=" + $p.Enabled)
  }
  $detail = ($detailParts -join "; ")

  Add-Row "Firewall enabled (Domain/Private/Public)" $status $detail
}
catch {
  Add-Row "Firewall enabled (Domain/Private/Public)" "Unknown" "Get-NetFirewallProfile failed"
}

# LLMNR disabled
try {
  $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue).EnableMulticast
  if ($null -eq $val) {
    Add-Row "LLMNR disabled" "Unknown" "EnableMulticast=Not set"
  }
  else {
    $ok = ($val -eq 0)
    $status = YesNo $ok
    $detail = "EnableMulticast=" + [string]$val
    Add-Row "LLMNR disabled" $status $detail
  }
}
catch {
  Add-Row "LLMNR disabled" "Unknown" "Registry read failed"
}

# ============================
# UAC / RDP / AUTOPLAY / AUDIT
# ============================

# UAC "Always Notify"
try {
  $psys = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  $consent   = $psys.ConsentPromptBehaviorAdmin
  $enableLUA = $psys.EnableLUA

  $consentDesc = "Unknown"
  if ($consent -eq 0) { $consentDesc = "Never notify (insecure)" }
  elseif ($consent -eq 1) { $consentDesc = "Notify without secure desktop" }
  elseif ($consent -eq 2) { $consentDesc = "Always notify (secure)" }

  $luaDesc = "Disabled"
  if ($enableLUA -eq 1) { $luaDesc = "Enabled" }

  $ok = ($consent -eq 2 -and $enableLUA -eq 1)

  $status = "No"
  if ($ok) { $status = "Yes" }

  $detail = "Prompt=$consentDesc (ConsentPromptBehaviorAdmin=$consent); UAC=$luaDesc (EnableLUA=$enableLUA)"
  Add-Row 'UAC "Always Notify"' $status $detail
}
catch {
  Add-Row 'UAC "Always Notify"' "Unknown" "Registry read failed"
}

# RDP disabled
try {
  $ts   = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server"
  $deny = $ts.fDenyTSConnections

  $status = "No"
  if ($deny -eq 1) { $status = "Yes" }

  $detail = "fDenyTSConnections=" + $deny
  Add-Row "RDP disabled" $status $detail
}
catch {
  Add-Row "RDP disabled" "Unknown" "Registry read failed"
}

# AutoPlay/AutoRun disabled
try {
  $hkml = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
  $hkcu = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun

  $hkmlOk = ($hkml -eq 255)
  $hkcuOk = ($hkcu -eq 255)

  $status = "No"
  if ($hkmlOk -and $hkcuOk) {
    $status = "Yes"
  }
  elseif ($hkmlOk -or $hkcuOk) {
    $status = "Partial"
  }

  $detail = "HKLM=" + [string]$hkml + "; HKCU=" + [string]$hkcu + " (expect 255)"
  Add-Row "AutoPlay/AutoRun disabled" $status $detail
}
catch {
  Add-Row "AutoPlay/AutoRun disabled" "Unknown" "Registry read failed"
}

# Audit policy summary
try {
  $audit = auditpol /get /category:* 2>$null
  if ($audit) {
    $snippetArray = $audit | Select-Object -First 20
    $snippet = ($snippetArray -join " | ")
    $detail = "auditpol sample: " + $snippet
    Add-Row "Audit policy (summary)" "Info" $detail
  }
  else {
    Add-Row "Audit policy (summary)" "Unknown" "auditpol returned no data"
  }
}
catch {
  Add-Row "Audit policy (summary)" "Unknown" "auditpol query failed"
}

# ============================
# SYSTEM RESTORE / BITLOCKER
# ============================

# System Restore enabled + storage (C:)
try {
  $srKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -ErrorAction SilentlyContinue
  $disableSR = $srKey.DisableSR
  $enabled = ($disableSR -ne 1)

  $status = "No"
  if ($enabled) { $status = "Yes" }

  $detail = "DisableSR=" + [string]$disableSR
  Add-Row "System Restore enabled (C:)" $status $detail

  $shadow = Get-CimInstance -ClassName Win32_ShadowStorage -ErrorAction SilentlyContinue |
            Where-Object { $_.Volume -match "C:" }

  if ($shadow) {
    $alloc = [uint64]$shadow.AllocatedSpace
    $max   = [uint64]$shadow.MaximumSpace
    $used  = [uint64]$shadow.UsedSpace

    $pct = 0
    if ($max -gt 0) {
      $pct = [math]::Round(($alloc / $max) * 100, 2)
    }

    $detail = "Allocated=" + (Format-Bytes $alloc) +
              "; Maximum=" + (Format-Bytes $max) +
              "; Used=" + (Format-Bytes $used) +
              "; Alloc%=" + $pct
    Add-Row "System Restore storage (C:)" "Info" $detail
  }
  else {
    Add-Row "System Restore storage (C:)" "Unknown" "No shadow storage binding for C: or access denied"
  }
}
catch {
  Add-Row "System Restore (C:)" "Unknown" "Query failed"
}

# BitLocker (C:)
try {
  $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
  if ($bl) {
    $prot = $bl.ProtectionStatus
    $status = "No"
    if ($prot -eq 'On') { $status = "Yes" }
    $detail = "ProtectionStatus=" + [string]$prot
    Add-Row "BitLocker enabled (C:)" $status $detail
  }
  else {
    Add-Row "BitLocker enabled (C:)" "Unknown" "BitLocker cmdlet not available or no volume info"
  }
}
catch {
  Add-Row "BitLocker enabled (C:)" "Unknown" "Query failed"
}

# ============================
# DISK SPACE / SMART / TYPE
# ============================

# Logical disk storage
try {
  $ldisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3"
  foreach ($d in $ldisks) {
    $size = [uint64]$d.Size
    $free = [uint64]$d.FreeSpace
    $used = $size - $free

    $pctFree = 0
    if ($size -gt 0) {
      $pctFree = [math]::Round(($free / $size) * 100, 2)
    }

    $status = "No"
    if ($pctFree -ge $MinFreePercent) { $status = "Yes" }

    $detail = "Drive=" + $d.DeviceID +
              "; Total=" + (Format-Bytes $size) +
              "; Free=" + (Format-Bytes $free) +
              "; Used=" + (Format-Bytes $used) +
              "; %Free=" + $pctFree
    Add-Row "Disk space healthy (>=$MinFreePercent% free)" $status $detail
  }
}
catch {
  Add-Row "Disk space (logical)" "Unknown" "Win32_LogicalDisk query failed"
}

# Physical disk SMART/health
$smartReported = $false
try {
  $pds = Get-PhysicalDisk -ErrorAction Stop
  foreach ($pd in $pds) {
    $hs = $pd.HealthStatus

    $status = "Unknown"
    if ($hs -eq 'Healthy') {
      $status = "Yes"
    }
    elseif ($hs -eq 'Warning' -or $hs -eq 'Unhealthy') {
      $status = "No"
    }

    $detail = "FriendlyName=" + $pd.FriendlyName +
              "; MediaType=" + $pd.MediaType +
              "; HealthStatus=" + $hs +
              "; Size=" + (Format-Bytes ([uint64]$pd.Size))
    Add-Row "SMART/Health (physical disk)" $status $detail
  }
  $smartReported = $true
}
catch { }

if (-not $smartReported) {
  try {
    $pred   = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop
    $drives = Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue

    foreach ($p in $pred) {
      $predictFail = $p.PredictFailure
      $model = $null

      if ($p.InstanceName -and $drives) {
        foreach ($d in $drives) {
          if ($p.InstanceName -like ("*" + $d.SerialNumber + "*") -or
              $p.InstanceName -like ("*" + $d.Model + "*")) {
            $model = $d.Model + " SN=" + $d.SerialNumber
            break
          }
        }
      }

      $status = "Yes"
      if ($predictFail -eq $true) { $status = "No" }

      if ([string]::IsNullOrEmpty($model)) {
        $diskText = $p.InstanceName
      }
      else {
        $diskText = $model
      }

      $detail = "PredictFailure=" + [string]$predictFail + "; Disk=" + $diskText
      Add-Row "SMART/FailurePredict (physical disk)" $status $detail
    }

    if (-not $pred) {
      Add-Row "SMART/FailurePredict (physical disk)" "Unknown" "No WMI data (root\wmi MSStorageDriver_FailurePredictStatus)"
    }
  }
  catch {
    Add-Row "SMART/FailurePredict (physical disk)" "Unknown" "SMART WMI query failed"
  }
}

# Physical disk type (SSD/HDD)
$diskTypeReported = $false
try {
  $pds2 = Get-PhysicalDisk -ErrorAction Stop
  foreach ($pd in $pds2) {
    $media = "Unknown"
    if ($pd.MediaType) { $media = $pd.MediaType.ToString() }

    $detail = "FriendlyName=" + $pd.FriendlyName +
              "; MediaType=" + $media +
              "; BusType=" + $pd.BusType +
              "; Size=" + (Format-Bytes ([uint64]$pd.Size))
    Add-Row "Physical disk type (SSD/HDD)" "Info" $detail
  }
  $diskTypeReported = $true
}
catch { }

if (-not $diskTypeReported) {
  try {
    $msft = Get-CimInstance -Namespace root\Microsoft\Windows\Storage -ClassName MSFT_PhysicalDisk -ErrorAction Stop
    foreach ($d in $msft) {
      $mt = "Unspecified"
      if ([int]$d.MediaType -eq 3) { $mt = "HDD" }
      elseif ([int]$d.MediaType -eq 4) { $mt = "SSD" }
      elseif ([int]$d.MediaType -eq 5) { $mt = "SCM" }

      $detail = "FriendlyName=" + $d.FriendlyName +
                "; MediaType=" + $mt +
                "; Size=" + (Format-Bytes ([uint64]$d.Size))
      Add-Row "Physical disk type (SSD/HDD)" "Info" $detail
    }
    $diskTypeReported = $true
  }
  catch { }
}

if (-not $diskTypeReported) {
  try {
    $wmiDisks = Get-CimInstance Win32_DiskDrive -ErrorAction Stop
    foreach ($wd in $wmiDisks) {
      $mediaGuess = "Unknown"
      if ($wd.RotationRate -ne $null) {
        $rot = [int]$wd.RotationRate
        if ($rot -gt 0) {
          $mediaGuess = "HDD (" + $rot + " RPM)"
        }
        else {
          $mediaGuess = "SSD/Unknown (0 RPM)"
        }
      }

      $detail = "Model=" + $wd.Model +
                "; MediaGuess=" + $mediaGuess +
                "; Size=" + (Format-Bytes ([uint64]$wd.Size))
      Add-Row "Physical disk type (SSD/HDD)" "Info" $detail
    }
  }
  catch {
    Add-Row "Physical disk type (SSD/HDD)" "Unknown" "Unable to determine disk type"
  }
}

# ============================
# OUTPUT & POST
# ============================

$Rows | Format-Table -AutoSize
$Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host ("CSV report: {0}" -f $CsvPath)

# Filter for send
if ($OnlySendNonCompliant) {
  $rowsToSend = $Rows | Where-Object { $_.status -eq "No" }
}
else {
  $rowsToSend = $Rows
}

$nonCompliantCount = ($Rows | Where-Object { $_.status -eq "No" }).Count

if ($WebhookUrl -and $rowsToSend.Count -gt 0) {
  [void](Send-ToN8N -Url $WebhookUrl -Rows $rowsToSend -TimeoutSec $HttpTimeoutSec -Retries $RetryCount -DelaySec $RetryDelaySec)
}
elseif (-not $WebhookUrl) {
  Write-Warning "WebhookUrl not set. Skipping POST."
}
else {
  Write-Host "Nothing to send (no rows or filtered to zero)."
}

if ($FailOnNonCompliant -and $nonCompliantCount -gt 0) {
  Write-Warning ("Non-compliant checks: {0}" -f $nonCompliantCount)
  exit 2
}
exit 0
