<#
.SYNOPSIS
    Enhanced device fingerprinting using Test-NetConnection, Resolve-DnsName, Get-NetNeighbor, and more.

.DESCRIPTION
    Collects identifying information about a device using native Windows networking cmdlets.
    Includes OS guessing based on TTL, ports, and banners.

.PARAMETER Target
    IP address or hostname of the target device

.PARAMETER DnsServer
    Optional - specific DNS server to query (helps discover internal DNS names)

.EXAMPLE
    .\Fingerprint-Device.ps1 -Target 192.168.1.47

.EXAMPLE
    .\Fingerprint-Device.ps1 -Target 10.66.5.120 -DnsServer 10.66.5.2
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [string]$DnsServer
)

Write-Host "`nDevice fingerprint - enhanced passive/active probes" -ForegroundColor Cyan
Write-Host "Target : $Target" -ForegroundColor Gray
Write-Host ("-" * 60) -ForegroundColor DarkGray

# ────────────────────────────────────────────────────────────────
#  1. Basic connectivity & important TCP ports
# ────────────────────────────────────────────────────────────────
Write-Host "`n[1] Connectivity & common open ports" -ForegroundColor Yellow

$commonPorts = @(22, 23, 53, 80, 443, 445, 3389, 5353, 62078, 9100, 515, 161, 137, 1900)

$portResults = @()
foreach ($port in $commonPorts) {
    $t = Test-NetConnection -ComputerName $Target -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
    $portResults += [pscustomobject]@{
        Port     = $port
        Open     = $t.TcpTestSucceeded
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
#  2. Reverse DNS / PTR record(s)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[2] Reverse DNS lookup (PTR)" -ForegroundColor Yellow

try {
    $ptrParams = @{
        Name = $Target
        Type = 'PTR'
        ErrorAction = 'Stop'
    }
    if ($DnsServer) { $ptrParams.Server = $DnsServer }
    $ptr = Resolve-DnsName @ptrParams

    if ($ptr) {
        $ptr | Select-Object Name, NameHost, QueryType, Server | Format-Table -AutoSize
    } else {
        Write-Host "  No PTR record found" -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "  PTR lookup failed: $($_.Exception.Message)" -ForegroundColor DarkRed
}

# ────────────────────────────────────────────────────────────────
#  3. Forward DNS lookups (A / AAAA) if target is hostname
# ────────────────────────────────────────────────────────────────
if ($Target -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
    Write-Host "`n[3] Forward DNS lookup (since target looks like hostname)" -ForegroundColor Yellow
    try {
        $fwd = Resolve-DnsName $Target -Type A,AAAA -ErrorAction Stop
        $fwd | Select-Object Name, IPAddress, QueryType | Format-Table -AutoSize
    }
    catch {
        Write-Host "  Forward lookup failed" -ForegroundColor DarkGray
    }
}

# ────────────────────────────────────────────────────────────────
#  4. ARP cache lookup using Get-NetNeighbor (same subnet only)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[4] ARP cache lookup (same subnet only)" -ForegroundColor Yellow

$ip = $null
try {
    # Resolve target to IP if it's a hostname
    if ($Target -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        $ip = $Target
    } else {
        $ipObj = Resolve-DnsName $Target -Type A -ErrorAction Stop | Select-Object -First 1
        $ip = $ipObj.IPAddress
    }

    # Ping once to populate ARP cache if needed
    $null = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue

    # Get ARP entry
    $neighbor = Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue

    if ($neighbor) {
        Write-Host "  Found in ARP cache:" -ForegroundColor Green
        $neighbor | Select-Object IPAddress, LinkLayerAddress, State | Format-Table -AutoSize

        # Extract MAC
        $mac = $neighbor.LinkLayerAddress
        if ($mac) {
            Write-Host "`n  MAC address  : $mac" -ForegroundColor Cyan

            # Basic OUI lookup hints
            $oui = ($mac -replace "[:-]", "").Substring(0,6).ToUpper()
            $hint = switch -Regex ($oui) {
                "^00(1E|C4|F5)"     { " (likely Sonos)" }
                "^00(25|26|90|F7)"  { " (possible Apple)" }
                "^0C(8B|FD)"        { " (possible Ubiquiti)" }
                "^10(0D|27|5F)"     { " (possible Samsung)" }
                "^14(EB|B6)"        { " (possible Ring / Amazon)" }
                "^18(EE|69)"        { " (possible Philips Hue)" }
                "^3C(15|C2)"        { " (possible Espressif / many IoT)" }
                "^44(6E|E1)"        { " (possible Wemo / Belkin)" }
                "^74(DA|DE)"        { " (possible TP-Link)" }
                "^78(5D|C4)"        { " (possible Fitbit)" }
                "^A0(63|91)"        { " (possible Netgear)" }
                "^B8(27|EB)"        { " (Raspberry Pi)" }
                "^DC(A6|EF)"        { " (possible Sonos / Nokia)" }
                "^F0(81|75)"        { " (possible Panasonic / Vizio)" }
                default             { "" }
            }
            if ($hint) { Write-Host "  Vendor hint  :$hint" -ForegroundColor Magenta }
        }
    } else {
        Write-Host "  No ARP entry found (different subnet or no recent communication?)" -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "  Could not get ARP entry: $($_.Exception.Message)" -ForegroundColor DarkRed
}

# ────────────────────────────────────────────────────────────────
#  5. HTTP/HTTPS banners (if ports open)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[5] HTTP/HTTPS server banners" -ForegroundColor Yellow

$httpOpen = $portResults | Where-Object { $_.Port -eq 80 -and $_.Open }
$httpsOpen = $portResults | Where-Object { $_.Port -eq 443 -and $_.Open }

if ($httpOpen -or $httpsOpen) {
    if ($httpOpen) {
        try {
            $httpResp = Invoke-WebRequest -Uri "http://$Target" -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            Write-Host "  HTTP Server: $($httpResp.Headers.Server)" -ForegroundColor Green
        } catch {
            Write-Host "  HTTP banner fetch failed: $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }

    if ($httpsOpen) {
        try {
            # Skip cert check if PS supports it (PS6+)
            $httpsParams = @{
                Uri = "https://$Target"
                Method = 'Head'
                UseBasicParsing = $true
                TimeoutSec = 5
                ErrorAction = 'Stop'
            }
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $httpsParams.SkipCertificateCheck = $true
            }
            $httpsResp = Invoke-WebRequest @httpsParams
            Write-Host "  HTTPS Server: $($httpsResp.Headers.Server)" -ForegroundColor Green
        } catch {
            Write-Host "  HTTPS banner fetch failed: $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }
} else {
    Write-Host "  No HTTP/HTTPS ports open" -ForegroundColor DarkGray
}

# ────────────────────────────────────────────────────────────────
#  6. TTL check for OS hint (from ping)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[6] Ping TTL check" -ForegroundColor Yellow

try {
    $pingResult = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
    $ttl = $pingResult.ResponseTimeToLive  # PS7+ or IPv4Address.TimeToLive in some versions

    if (-not $ttl) {
        # Fallback to parsing ping.exe for compatibility
        $pingOutput = ping $Target -n 1
        if ($pingOutput -match "TTL=(\d+)") {
            $ttl = $Matches[1]
        }
    }

    if ($ttl) {
        Write-Host "  TTL: $ttl" -ForegroundColor Green
    } else {
        Write-Host "  Could not determine TTL" -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "  Ping failed: $($_.Exception.Message)" -ForegroundColor DarkRed
    $ttl = $null
}

# ────────────────────────────────────────────────────────────────
#  7. Basic SNMP query (if port 161 open) - requires community 'public'
# ────────────────────────────────────────────────────────────────
$snmpOpen = $portResults | Where-Object { $_.Port -eq 161 -and $_.Open }
if ($snmpOpen) {
    Write-Host "`n[7] Basic SNMP query (community: public)" -ForegroundColor Yellow
    try {
        # Note: PowerShell doesn't have built-in SNMP, so use a simple UDP client for sysDescr (OID 1.3.6.1.2.1.1.1.0)
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Connect($Target, 161)
        
        # Basic GET request for sysDescr - this is a hardcoded ASN.1 BER encoded packet for 'public' community
        $snmpGet = [byte[]]@(0x30,0x29,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x1c,0x02,0x04,0x01,0x00,0x00,0x00,0x01,0x00,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0e,0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00)
        
        $null = $udpClient.Send($snmpGet, $snmpGet.Length)
        $response = $udpClient.Receive([ref]$endpoint)
        $udpClient.Close()
        
        # Extract sysDescr from response (simplified, assumes success)
        $sysDescr = [System.Text.Encoding]::ASCII.GetString($response[($response.Length - ($response[-2] + 2))..($response.Length - 3)])
        Write-Host "  SNMP sysDescr: $sysDescr" -ForegroundColor Green
    } catch {
        Write-Host "  SNMP query failed (no response or wrong community?): $($_.Exception.Message)" -ForegroundColor DarkRed
        $sysDescr = $null
    }
} else {
    Write-Host "`n[7] SNMP: Port 161 not open" -ForegroundColor DarkGray
    $sysDescr = $null
}

# ────────────────────────────────────────────────────────────────
#  8. mDNS / SSDP hints (basic, no queries - just port presence)
# ────────────────────────────────────────────────────────────────
Write-Host "`n[8] mDNS / SSDP presence hints" -ForegroundColor Yellow

$mdnsOpen = $portResults | Where-Object { $_.Port -eq 5353 -and $_.Open }
$ssdpOpen = $portResults | Where-Object { $_.Port -eq 1900 -and $_.Open }

if ($mdnsOpen) {
    Write-Host "  mDNS (5353) open: Likely Apple device or Linux with Avahi" -ForegroundColor Green
}
if ($ssdpOpen) {
    Write-Host "  SSDP (1900) open: UPnP device, often Windows, smart TVs, or IoT" -ForegroundColor Green
}
if (-not $mdnsOpen -and -not $ssdpOpen) {
    Write-Host "  No mDNS or SSDP ports open" -ForegroundColor DarkGray
}

# Note: For full mDNS/SSDP queries, you'd need to send multicast UDP packets, which can be done with .NET sockets similar to SNMP above, but omitted for simplicity.

# ────────────────────────────────────────────────────────────────
#  9. OS Guess based on collected info
# ────────────────────────────────────────────────────────────────
Write-Host "`n[9] OS Guess" -ForegroundColor Yellow

$osHints = @()

# TTL hints
if ($ttl) {
    if ($ttl -le 64) { $osHints += "Linux/Unix (TTL <=64)" }
    elseif ($ttl -le 128) { $osHints += "Windows (TTL ~128)" }
    elseif ($ttl -le 255) { $osHints += "Network device/Solaris (TTL 255)" }
}

# Port hints
$hasRDP = $portResults | Where-Object { $_.Port -eq 3389 -and $_.Open }
$hasSMB = $portResults | Where-Object { $_.Port -eq 445 -and $_.Open }
$hasSSH = $portResults | Where-Object { $_.Port -eq 22 -and $_.Open }
$hasNetBIOS = $portResults | Where-Object { $_.Port -eq 137 -and $_.Open }

if ($hasRDP) { $osHints += "Windows (RDP open)" }
if ($hasSMB -and $hasNetBIOS) { $osHints += "Windows (SMB + NetBIOS)" }
if ($hasSSH -and -not $hasSMB) { $osHints += "Linux (SSH open, no SMB)" }
if ($mdnsOpen -and -not $hasSMB) { $osHints += "Linux/macOS (mDNS open, no SMB)" }

# Banner hints
if ($httpResp.Headers.Server -match "IIS|Microsoft") { $osHints += "Windows (IIS/Microsoft server)" }
if ($httpsResp.Headers.Server -match "IIS|Microsoft") { $osHints += "Windows (IIS/Microsoft server)" }
if ($httpResp.Headers.Server -match "Apache|nginx") { $osHints += "Linux (Apache/nginx server)" }
if ($httpsResp.Headers.Server -match "Apache|nginx") { $osHints += "Linux (Apache/nginx server)" }

# SNMP hint
if ($sysDescr -match "Windows") { $osHints += "Windows (SNMP sysDescr)" }
if ($sysDescr -match "Linux|Ubuntu|Debian|CentOS") { $osHints += "Linux (SNMP sysDescr)" }

if ($osHints.Count -eq 0) {
    Write-Host "  No strong OS hints detected" -ForegroundColor DarkGray
} else {
    $windowsCount = ($osHints | Where-Object { $_ -match "Windows" }).Count
    $linuxCount = ($osHints | Where-Object { $_ -match "Linux" }).Count

    if ($windowsCount -gt $linuxCount) {
        Write-Host "  Likely Windows machine" -ForegroundColor Magenta
    } elseif ($linuxCount -gt $windowsCount) {
        Write-Host "  Likely Linux machine" -ForegroundColor Magenta
    } else {
        Write-Host "  Mixed hints - could be either Windows or Linux" -ForegroundColor Magenta
    }
    $osHints | ForEach-Object { Write-Host "    - $_" }
}

Write-Host "`n`nFingerprint complete." -ForegroundColor Cyan
