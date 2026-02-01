<#
.SYNOPSIS
    Enhanced device fingerprinting using native PowerShell cmdlets.

.DESCRIPTION
    Collects connectivity, DNS, ARP, HTTP headers, SNMP, TTL, and other signals
    to help identify and fingerprint a target device (especially Linux vs Windows).

.PARAMETER Target
    IP address or hostname of the target device

.PARAMETER DnsServer
    Optional - specific DNS server to use for queries

.EXAMPLE
    .\Fingerprint-Device.ps1 -Target 192.168.1.100

.EXAMPLE
    .\Fingerprint-Device.ps1 -Target printer.local -DnsServer 192.168.1.1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [string]$DnsServer
)

Write-Host "`nDevice Fingerprint - Enhanced Scan" -ForegroundColor Cyan
Write-Host "Target : $Target" -ForegroundColor Gray
Write-Host ("-" * 70) -ForegroundColor DarkGray

# ────────────────────────────────────────────────────────────────
#  1. Connectivity & common open ports
# ────────────────────────────────────────────────────────────────
Write-Host "`n[1] Common Ports Scan" -ForegroundColor Yellow

$commonPorts = @(22, 23, 53, 80, 443, 445, 3389, 5353, 62078, 9100, 515, 161, 137, 1900)

$portResults = @()
foreach ($port in $commonPorts) {
    $t = Test-NetConnection -ComputerName $Target -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
    $portResults += [pscustomobject]@{
        Port        = $port
        Open        = $t.TcpTestSucceeded
        ServiceHint = switch ($port) {
            22     { "SSH" }
            23     { "Telnet" }
            53     { "DNS" }
            80     { "HTTP" }
            443    { "HTTPS" }
            445    { "SMB / Windows File Sharing" }
            3389   { "RDP" }
            5353   { "mDNS / Bonjour" }
            62078  { "iPhone sync / iTunes Wi-Fi" }
            9100   { "JetDirect / raw printer" }
            515    { "LPD / Line Printer Daemon" }
            161    { "SNMP" }
            137    { "NetBIOS Name Service" }
            1900   { "UPnP / SSDP" }
            default { "" }
        }
    }
}

$openPorts = $portResults | Where-Object { $_.Open }
if ($openPorts.Count -eq 0) {
    Write-Host "  No common ports responded" -ForegroundColor DarkGray
} else {
    $openPorts | Sort-Object Port | Format-Table -AutoSize
}

# ────────────────────────────────────────────────────────────────
#  2. Reverse DNS (PTR)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[2] Reverse DNS (PTR)" -ForegroundColor Yellow

try {
    $ptrParams = @{ Name = $Target; Type = 'PTR'; ErrorAction = 'Stop' }
    if ($DnsServer) { $ptrParams.Server = $DnsServer }
    $ptr = Resolve-DnsName @ptrParams
    if ($ptr) {
        $ptr | Select-Object Name, NameHost, QueryType, Server | Format-Table -AutoSize
    } else {
        Write-Host "  No PTR record" -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "  PTR lookup failed: $($_.Exception.Message)" -ForegroundColor DarkRed
}

# ────────────────────────────────────────────────────────────────
#  3. Forward DNS (if hostname provided)
# ────────────────────────────────────────────────────────────────
if ($Target -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and $Target -notmatch "^[a-fA-F0-9:]+$") {
    Write-Host "`n[3] Forward DNS (A/AAAA)" -ForegroundColor Yellow
    try {
        $fwd = Resolve-DnsName $Target -Type A,AAAA -ErrorAction Stop
        $fwd | Select-Object Name, IPAddress, QueryType | Format-Table -AutoSize
    }
    catch {
        Write-Host "  Forward lookup failed" -ForegroundColor DarkGray
    }
}

# ────────────────────────────────────────────────────────────────
#  4. ARP / Neighbor cache (same subnet only)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[4] ARP / Neighbor Cache" -ForegroundColor Yellow

$ip = $null
try {
    if ($Target -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        $ip = $Target
    } else {
        $ipObj = Resolve-DnsName $Target -Type A -ErrorAction Stop | Select-Object -First 1
        $ip = $ipObj.IPAddress
    }

    # Populate cache if needed
    $null = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue

    $neighbor = Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue
    if ($neighbor) {
        $neighbor | Select-Object IPAddress, LinkLayerAddress, State | Format-Table -AutoSize
        $mac = $neighbor.LinkLayerAddress
        if ($mac) {
            Write-Host "  MAC: $mac" -ForegroundColor Cyan
            $oui = ($mac -replace "[:-]", "").Substring(0,6).ToUpper()
            $hint = switch -Regex ($oui) {
                "^B8(27|EB)"       { " (Raspberry Pi)" }
                "^00(25|26|90|F7)" { " (possible Apple)" }
                "^3C(15|C2)"       { " (Espressif / many IoT)" }
                "^74(DA|DE)"       { " (possible TP-Link)" }
                "^A0(63|91)"       { " (possible Netgear)" }
                default            { "" }
            }
            if ($hint) { Write-Host "  Vendor hint:$hint" -ForegroundColor Magenta }
        }
    } else {
        Write-Host "  No ARP entry (different subnet?)" -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "  ARP lookup failed: $($_.Exception.Message)" -ForegroundColor DarkRed
}

# ────────────────────────────────────────────────────────────────
#  5. HTTP/HTTPS banners
# ────────────────────────────────────────────────────────────────
Write-Host "`n[5] HTTP/HTTPS Server Banner" -ForegroundColor Yellow

$httpOpen  = $portResults | Where-Object { $_.Port -eq 80  -and $_.Open }
$httpsOpen = $portResults | Where-Object { $_.Port -eq 443 -and $_.Open }

if (-not $httpOpen -and -not $httpsOpen) {
    Write-Host "  No HTTP/HTTPS ports open" -ForegroundColor DarkGray
} else {
    if ($httpOpen) {
        try {
            $resp = Invoke-WebRequest -Uri "http://$($Target)" -Method Head -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
            if ($resp.Headers.Server) {
                Write-Host "  HTTP Server: $($resp.Headers.Server)" -ForegroundColor Green
            } else {
                Write-Host "  HTTP - no Server header" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  HTTP banner failed: $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }

    if ($httpsOpen) {
        try {
            $params = @{
                Uri            = "https://$($Target)"
                Method         = 'Head'
                UseBasicParsing = $true
                TimeoutSec     = 6
                ErrorAction    = 'Stop'
            }
            if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
            $resp = Invoke-WebRequest @params
            if ($resp.Headers.Server) {
                Write-Host "  HTTPS Server: $($resp.Headers.Server)" -ForegroundColor Green
            } else {
                Write-Host "  HTTPS - no Server header" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  HTTPS banner failed: $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }
}

# ────────────────────────────────────────────────────────────────
#  6. Multiple pings → TTL collection
# ────────────────────────────────────────────────────────────────
Write-Host "`n[6] Ping TTL (multiple attempts)" -ForegroundColor Yellow

$ttlValues = @()
$maxTtl = $null

try {
    $pings = Test-Connection -ComputerName $Target -Count 4 -ErrorAction Stop
    foreach ($p in $pings) {
        $ttl = if ($p.PSObject.Properties['ResponseTimeToLive']) {
            $p.ResponseTimeToLive
        } elseif ($p.PSObject.Properties['TimeToLive']) {
            $p.TimeToLive
        } else { $null }

        if ($ttl) {
            $ttlValues += $ttl
            Write-Host "  TTL: $ttl   (RTT: $($p.ResponseTime) ms)" -ForegroundColor Green
        }
    }
    if ($ttlValues.Count -gt 0) {
        $maxTtl = ($ttlValues | Measure-Object -Maximum).Maximum
        Write-Host "`n  Highest TTL (most reliable): $maxTtl" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "  Test-Connection failed: $($_.Exception.Message)" -ForegroundColor DarkRed
}

# Fallback: ping.exe parsing
if (-not $maxTtl -and $ttlValues.Count -eq 0) {
    Write-Host "  Trying ping.exe fallback..." -ForegroundColor Yellow
    $output = ping $Target -n 4 2>$null
    if ($output) {
        foreach ($line in $output) {
            if ($line -match "TTL=(\d+)") {
                $ttl = [int]$Matches[1]
                $ttlValues += $ttl
                Write-Host "  Parsed TTL: $ttl" -ForegroundColor Green
            }
        }
        if ($ttlValues) {
            $maxTtl = ($ttlValues | Measure-Object -Maximum).Maximum
            Write-Host "  Highest parsed TTL: $maxTtl" -ForegroundColor Cyan
        }
    }
}

if (-not $maxTtl) {
    Write-Host "  Could not obtain TTL" -ForegroundColor DarkGray
}

# ────────────────────────────────────────────────────────────────
#  7. Basic SNMP sysDescr (port 161 + public community)
# ────────────────────────────────────────────────────────────────
$snmpOpen = $portResults | Where-Object { $_.Port -eq 161 -and $_.Open }
$sysDescr = $null

if ($snmpOpen -and $ip) {
    Write-Host "`n[7] SNMP sysDescr (public community)" -ForegroundColor Yellow
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Connect($ip, 161)
        # Minimal GET for sysDescr.1.0 (1.3.6.1.2.1.1.1.0) with community 'public'
        $packet = [byte[]](
            0x30,0x29,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,
            0xa0,0x1c,0x02,0x04,0x12,0x34,0x56,0x78,0x02,0x01,0x00,0x02,0x01,0x00,
            0x30,0x0e,0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00
        )
        $null = $udp.Send($packet, $packet.Length)
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref]$endpoint)
        $udp.Close()

        # Crude extraction of printable string after the OID
        $text = [System.Text.Encoding]::ASCII.GetString($response)
        if ($text -match '([ -~]{8,})') {
            $sysDescr = $Matches[1].Trim()
            Write-Host "  sysDescr: $sysDescr" -ForegroundColor Green
        } else {
            Write-Host "  Got response but could not parse sysDescr" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  SNMP query failed: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
} else {
    Write-Host "`n[7] SNMP: port 161 not open or no IP" -ForegroundColor DarkGray
}

# ────────────────────────────────────────────────────────────────
#  8. OS Guess
# ────────────────────────────────────────────────────────────────
Write-Host "`n[8] OS / Device Guess" -ForegroundColor Yellow

$osHints = @()

if ($maxTtl) {
    if     ($maxTtl -le 64)  { $osHints += "Linux / macOS / Unix-like (TTL ≤ 64)" }
    elseif ($maxTtl -le 128) { $osHints += "Windows (TTL ≈ 128)" }
    elseif ($maxTtl -le 255) { $osHints += "Network appliance / Cisco / Solaris (TTL 255)" }
    else                     { $osHints += "Unusual TTL: $maxTtl" }
}

$hasRDP     = $openPorts | Where-Object Port -eq 3389
$hasSMB     = $openPorts | Where-Object Port -eq 445
$hasNetBIOS = $openPorts | Where-Object Port -eq 137
$hasSSH     = $openPorts | Where-Object Port -eq 22
$hasmDNS    = $openPorts | Where-Object Port -eq 5353

if ($hasRDP)     { $osHints += "Windows (RDP open)" }
if ($hasSMB -and $hasNetBIOS) { $osHints += "Windows (SMB + NetBIOS)" }
if ($hasSSH -and -not ($hasSMB -or $hasRDP)) { $osHints += "Likely Linux/Unix (SSH, no Windows ports)" }

$serverBanner = ""
if ($httpOpen)  { $serverBanner += $resp.Headers.Server + " " }
if ($httpsOpen) { $serverBanner += $resp.Headers.Server + " " }

if ($serverBanner -match "IIS|Microsoft") { $osHints += "Windows (IIS / Microsoft server)" }
if ($serverBanner -match "Apache|nginx|lighttpd") { $osHints += "Linux / Unix-like (Apache/nginx)" }

if ($sysDescr) {
    if ($sysDescr -match "Windows") { $osHints += "Windows (SNMP)" }
    if ($sysDescr -match "Linux|Ubuntu|Debian|CentOS|Fedora|Raspbian") { $osHints += "Linux (SNMP)" }
}

if ($osHints.Count -eq 0) {
    Write-Host "  No strong OS hints found" -ForegroundColor DarkGray
} else {
    $winCount  = ($osHints | Where-Object { $_ -match "Windows" }).Count
    $linuxCount = ($osHints | Where-Object { $_ -match "Linux|Unix" }).Count

    if ($winCount -gt $linuxCount) {
        Write-Host "  → Most likely **Windows**" -ForegroundColor Magenta
    } elseif ($linuxCount -gt $winCount) {
        Write-Host "  → Most likely **Linux / Unix-like**" -ForegroundColor Magenta
    } else {
        Write-Host "  → Mixed / inconclusive hints" -ForegroundColor Magenta
    }

    $osHints | ForEach-Object { Write-Host "    • $_" }
}

Write-Host "`nFingerprint scan complete." -ForegroundColor Cyan
