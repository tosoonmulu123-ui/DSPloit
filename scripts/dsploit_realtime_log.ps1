# ==============================================================================
#  DSPloit Real-Time Log — Windows PowerShell
#  Captures step-by-step breadcrumb dari JailbreakEngine + TrustCacheInjector
#  + ExpAmfidPatch langsung via syslog relay (NSLog -> idevicesyslog)
#
#  Cara pakai:
#    1. Install libimobiledevice:
#       https://github.com/jrjr/libimobiledevice-windows/releases
#    2. Extract, tambah folder ke PATH
#    3. Colok iPhone via USB, Trust di iPhone
#    4. Buka PowerShell
#    5. .\scripts\dsploit_realtime_log.ps1
#    6. Buka DSPloit di iPhone -> tap Jailbreak
# ==============================================================================

# -- CONFIG --
$LogFile  = "logs\dsploit_session_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$AppBundle = "com.royan.dsploit"

$IncludePattern = [regex]"(?i)(DSPloit\]|" +
    "\(jb\)|\(tc79\)|\(exp_amfid\)|" +
    "JailbreakEngine|TrustCacheInject|" +
    "step[0-9]_|step [0-9]|" +
    "darksword|DarkSword|" +
    "KRW|krw_persist|" +
    "offsets_|XPF|kcache|kernelcache|" +
    "exploit_select|EXPLOIT_|jpeg_uaf|" +
    "sepkeystore|aks_close|" +
    "VFS|vfsinit|sbxescape|sandbox|" +
    "SpringBoard|RemoteCall|rcinit|rcready|" +
    "launchd|RootExecutor|uid=|getuid|" +
    "bootstrap|var.jb|dsploit_bootstrap|" +
    "AMFI|amfi|amfid|cs_enforcement|" +
    "TrustCache|trustcache|LoadTrustCache|" +
    "MSM|MobileStorage|CDHash|cdhash|" +
    "PPL|KTRR|CTRR|" +
    "panic|fault|abort|SIGKILL|signal|" +
    "Starting jailbreak|Jailbreak complete|" +
    "Failed after|retry|retryChain|" +
    "fast recovery|persisted KRW|" +
    "Fetching kernelcache|XPF ready)"

$ExcludePattern = [regex]"(?i)(Faulty glyph|Gesture:|tcp_output|" +
    "UITouch|gestureRecognizer|NSLayoutConstraint|" +
    "SwiftUI\.UIHostingView|OSLOG|" +
    "UIScrollView|UILongPress|_UISwipe|_UISecondary)"

$StepLabels = @{
    "Running darksword"     = "STEP 1a - DarkSword exploit running"
    "KRW recovered"         = "STEP 1 - KRW fast recovery (persisted)"
    "Offsets resolved"      = "STEP 1b - XPF offset resolution"
    "VFS ready"             = "STEP 2a - VFS OK"
    "Sandbox escaped"       = "STEP 2b - Sandbox escaped"
    "SpringBoard connected" = "STEP 3 - RemoteCall to SpringBoard OK"
    "Root confirmed"        = "STEP 4 - Root (uid=0) confirmed"
    "Bootstrap ready"       = "STEP 5 - Bootstrap dirs created"
    "AMFI disabled"         = "STEP 6 - AMFI flags zeroed"
    "Trust cache injected"  = "STEP 7 - TrustCache OK via MSM"
    "Jailbreak complete"    = "FINISH - Done"
    "Strategy B"            = "AMFID - Strategy B: Kill+Race"
    "Strategy D"            = "AMFID - Strategy D: Patch __TEXT"
    "Starting jailbreak"    = "START - Jailbreak chain initiated"
}

# -- FUNCTIONS --
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  DSPloit Real-Time Log - Windows" -ForegroundColor Cyan
    Write-Host "  JailbreakEngine step-by-step via idevicesyslog" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Log file : $LogFile" -ForegroundColor Gray
    Write-Host "  Filter   : [DSPloit] (jb) (exp_amfid) + step labels" -ForegroundColor Gray
    Write-Host "  Stop     : Ctrl+C" -ForegroundColor Gray
    Write-Host ""
}

function Get-StepLabel($line) {
    foreach ($key in $StepLabels.Keys) {
        if ($line -match [regex]::Escape($key)) {
            return $StepLabels[$key]
        }
    }
    return $null
}

function Write-LogLine($stepNum, $time, $label, $raw) {
    if ($raw -match "panic|SIGKILL|fault|abort") {
        $color = "Red"
    } elseif ($raw -match "Failed|failed|ERROR|error") {
        $color = "Red"
    } elseif ($raw -match "Warning|warning|retry") {
        $color = "Yellow"
    } elseif ($raw -match "success|confirmed|ready|OK|complete") {
        $color = "Green"
    } elseif ($raw -match "darksword|DarkSword|KRW|exploit") {
        $color = "Cyan"
    } elseif ($raw -match "AMFI|amfi|amfid") {
        $color = "Yellow"
    } else {
        $color = "White"
    }

    if ($label) {
        Write-Host ""
        Write-Host "  --- $label ---" -ForegroundColor DarkGray
    }

    Write-Host "[$($stepNum.ToString('000'))][$time] $raw" -ForegroundColor $color
}

# -- MAIN --
Write-Banner

# Check idevicesyslog
if (-not (Get-Command "idevicesyslog" -ErrorAction SilentlyContinue)) {
    Write-Host "  ERROR: idevicesyslog not found in PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Download from:" -ForegroundColor Yellow
    Write-Host "  https://github.com/jrjr/libimobiledevice-windows/releases" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Extract, then add folder to PATH:" -ForegroundColor Gray
    Write-Host '  $env:PATH += ";C:\path\to\libimobiledevice"' -ForegroundColor Gray
    Write-Host ""
    Read-Host "  Press Enter to exit"
    exit 1
}

# Create logs dir
if (-not (Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }

# Pair device
Write-Host "  Connecting to device..." -ForegroundColor Gray
$pairResult = idevicepair pair 2>&1
if ($pairResult -match "SUCCESS|already") {
    Write-Host "  Device connected and trusted." -ForegroundColor Green
} else {
    Write-Host "  $pairResult" -ForegroundColor Yellow
    Write-Host "  Make sure you tapped Trust on iPhone." -ForegroundColor Gray
}

# Write log header
$header = "DSPloit Real-Time Log - $(Get-Date)`nFilter: [DSPloit] NSLog + step labels`n"
Set-Content $LogFile $header

Write-Host ""
Write-Host "  Buka DSPloit di iPhone sekarang." -ForegroundColor White
Write-Host "  Log muncul saat app aktif (NSLog capture)." -ForegroundColor Gray
Write-Host ""

$stepCounter = 0
$lastStepLabel = ""
$panicDetected = $false

# Stream syslog with filter
idevicesyslog 2>$null | ForEach-Object {
    $rawLine = $_

    if ([string]::IsNullOrWhiteSpace($rawLine)) { return }
    if ($ExcludePattern.IsMatch($rawLine)) { return }

    $isRelevant = $IncludePattern.IsMatch($rawLine)
    if (-not $isRelevant) { return }

    $stepCounter++
    $time = Get-Date -Format "HH:mm:ss.fff"

    # Detect step label
    $stepLabel = Get-StepLabel $rawLine
    if ($stepLabel -and $stepLabel -ne $lastStepLabel) {
        $lastStepLabel = $stepLabel
    } else {
        $stepLabel = $null
    }

    # Detect panic
    if ($rawLine -match "panic|kernel panic") {
        $panicDetected = $true
        $msg = "`n  PANIC DETECTED AT STEP $stepCounter [$time]`n"
        Write-Host $msg -ForegroundColor Red
        Add-Content $LogFile $msg
        Add-Content $LogFile "  LAST LOG: $rawLine"
    }

    # Display + save
    Write-LogLine $stepCounter $time $stepLabel $rawLine
    Add-Content $LogFile "[$($stepCounter.ToString('000'))][$time] $rawLine"
}

# After stream stops
Write-Host ""
Write-Host "  Stream stopped. Total steps: $stepCounter" -ForegroundColor White
Write-Host "  Log saved: $LogFile" -ForegroundColor Yellow
if ($panicDetected) {
    Write-Host ""
    Write-Host "  PANIC detected during session." -ForegroundColor Red
    Write-Host "  Check last step in log for trigger point." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Get full panic log:" -ForegroundColor Gray
    Write-Host "  idevicecrashreport -e -k .\logs\panic\" -ForegroundColor Cyan
}
