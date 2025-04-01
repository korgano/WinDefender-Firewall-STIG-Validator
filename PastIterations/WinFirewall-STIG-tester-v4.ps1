# Function to check if running as Administrator
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Log admin permission status
$desktop = [Environment]::GetFolderPath("Desktop")
$logFile = Join-Path $desktop "WinFirewall-STIG-actions.txt"
if (Test-Admin) {
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Script running with administrative privileges."
} else {
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Warning: Script is not running with administrative privileges. Some commands may fail."
}

# Function to retrieve registry value from multiple paths
function Get-RegValue {
    param (
        [string[]]$Paths,
        [string]$PropertyName
    )
    foreach ($path in $Paths) {
        try {
            $reg = Get-ItemProperty -Path $path -ErrorAction Stop
            if ($null -ne $reg.$PropertyName) {
                return $reg.$PropertyName
            }
        } catch {
            continue
        }
    }
    return $null
}

# Function to validate that a registry setting equals an expected value
function Validate-Setting {
    param (
        [string[]]$Paths,
        [string]$PropertyName,
        [Object]$ExpectedValue
    )
    $currentValue = Get-RegValue -Paths $Paths -PropertyName $PropertyName
    if ($currentValue -eq $ExpectedValue) {
        return $true
    } else {
        return $false
    }
}

# Mapping of Findings to their Descriptions
$descriptions = @{
    "V-241989" = "Windows Defender Firewall must be enabled when connected to a domain."
    "V-241990" = "Windows Defender Firewall must be enabled when connected to a private network."
    "V-241991" = "Windows Defender Firewall must be enabled when connected to a public network."
    "V-241992" = "Windows Defender Firewall must block unsolicited inbound connections when connected to a domain."
    "V-241993" = "Windows Defender Firewall must allow outbound connections, unless explicitly blocked by rule."
    "V-241994" = "Windows Defender Firewall log size must be configured for domain connections."
    "V-241995" = "Windows Defender Firewall must log dropped packets when connected to a domain."
    "V-241996" = "Windows Defender Firewall must log successful connections when connected to a domain."
    "V-241997" = "Windows Defender Firewall must block unsolicited inbound connections when connected to a private network."
    "V-241998" = "Windows Defender Firewall must allow outbound connections on a private network, unless explicitly blocked by rule."
    "V-241999" = "Windows Defender Firewall log size must be configured for private network connections."
    "V-242000" = "Windows Defender Firewall must log dropped packets when connected to a private network."
    "V-242001" = "Windows Defender Firewall must log successful connections when connected to a private network."
    "V-242002" = "Windows Defender Firewall must block unsolicited inbound connections when connected to a public network."
    "V-242003" = "Windows Defender Firewall must allow outbound connections on a public network, unless explicitly blocked by rule."
    "V-242004" = "Windows Defender Firewall public network connections must not merge local firewall rules with Group policy settings."
    "V-242005" = "Windows Defender Firewall public network connections must not merge local connection rules with Group policy settings."
    "V-242006" = "Windows Defender Firewall log size must be configured for public connections."
    "V-242007" = "Windows Defender Firewall must log dropped packets when connected to a public network."
    "V-242008" = "Windows Defender Firewall must log successful connections when connected to a public network."
}

# Set paths for CSV file
$csvPath = Join-Path $desktop "WinFirewall-STIG-Checklist.csv"

# Clear previous log contents
"" | Out-File -FilePath $logFile

# Array to hold CSV objects
$results = @()

# ------------------- ROW 1 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241989"
    checkid     = "C-45264r921981_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241989"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
)
$property = "EnableFirewall"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241989 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles state on | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241989 - Executed command: netsh advfirewall set allprofiles state on"
    # Validate the change
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241989 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241989 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 2 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241990"
    checkid     = "C-45265r921984_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241990"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
)
$property = "EnableFirewall"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241990 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles state on | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241990 - Executed command: netsh advfirewall set allprofiles state on"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241990 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241990 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 3 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241991"
    checkid     = "C-45266r921987_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241991"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
)
$property = "EnableFirewall"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241991 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles state on | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241991 - Executed command: netsh advfirewall set allprofiles state on"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241991 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241991 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 4 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241992"
    checkid     = "C-45267r698215_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241992"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
)
$property = "DefaultInboundAction"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241992 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241992 - Executed command: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241992 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241992 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 5 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241993"
    checkid     = "C-45268r698218_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241993"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
)
$property = "DefaultOutboundAction"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241993 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241993 - Executed command: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 0) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241993 - Correction validated; value updated to 0"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241993 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 6 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241994"
    checkid     = "C-45269r698221_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241994"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"
)
$property = "LogFileSize"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -ge 16384) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241994 - LogFileSize is adequate ($origValue)"
} else {
    netsh advfirewall set domainprofile logging maxfilesize 16384 | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241994 - Executed command: netsh advfirewall set domainprofile logging maxfilesize 16384"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 16384) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241994 - Correction validated; LogFileSize updated to 16384"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241994 - Correction FAILED; LogFileSize remains $origValue"
    }
}
$results += $row

# ------------------- ROW 7 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241995"
    checkid     = "C-45270r698224_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241995"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
)
$property = "LogDroppedPackets"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241995 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241995 - Executed command: netsh advfirewall set allprofiles logging droppedconnections enable"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241995 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241995 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 8 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241996"
    checkid     = "C-45271r698227_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241996"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
)
$property = "LogSuccessfulConnections"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241996 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241996 - Executed command: netsh advfirewall set allprofiles logging allowedconnections enable"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241996 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241996 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 9 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241997"
    checkid     = "C-45272r698230_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241997"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
)
$property = "DefaultInboundAction"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241997 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241997 - Executed command: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241997 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241997 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 10 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241998"
    checkid     = "C-45273r698233_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241998"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
)
$property = "DefaultOutboundAction"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241998 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241998 - Executed command: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 0) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241998 - Correction validated; value updated to 0"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241998 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 11 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-241999"
    checkid     = "C-45274r698236_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-241999"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"
)
$property = "LogFileSize"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -ge 16384) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241999 - LogFileSize is adequate ($origValue)"
} else {
    netsh advfirewall set privateprofile logging maxfilesize 16384 | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241999 - Executed command: netsh advfirewall set privateprofile logging maxfilesize 16384"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 16384) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241999 - Correction validated; LogFileSize updated to 16384"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-241999 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 12 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242000"
    checkid     = "C-45275r698239_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242000"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
)
$property = "LogDroppedPackets"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242000 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242000 - Executed command: netsh advfirewall set allprofiles logging droppedconnections enable"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242000 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242000 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 13 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242001"
    checkid     = "C-45276r698242_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242001"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
)
$property = "LogSuccessfulConnections"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242001 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242001 - Executed command: netsh advfirewall set allprofiles logging allowedconnections enable"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242001 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242001 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 14 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242002"
    checkid     = "C-45277r698245_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242002"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
)
$property = "DefaultInboundAction"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242002 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242002 - Executed command: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242002 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242002 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 15 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242003"
    checkid     = "C-45278r698248_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242003"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
)
$property = "DefaultOutboundAction"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242003 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242003 - Executed command: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 0) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242003 - Correction validated; value updated to 0"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242003 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 16 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242004"
    checkid     = "C-45279r698251_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242004"]
}
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$property = "AllowLocalPolicyMerge"
$origValue = Get-RegValue -Paths @($regPath) -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242004 - AllowLocalPolicyMerge is 0; no correction needed"
} else {
    # No command executed per instructions
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242004 - AllowLocalPolicyMerge is not 0; no correction executed"
}
$results += $row

# ------------------- ROW 17 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242005"
    checkid     = "C-45280r698254_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242005"]
}
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$property = "AllowLocalIPsecPolicyMerge"
$origValue = Get-RegValue -Paths @($regPath) -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242005 - AllowLocalIPsecPolicyMerge is 0; no correction needed"
} else {
    # No command executed per instructions
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242005 - AllowLocalIPsecPolicyMerge is not 0; no correction executed"
}
$results += $row

# ------------------- ROW 18 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242006"
    checkid     = "C-45281r698257_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242006"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"
)
$property = "LogFileSize"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -ge 16384) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242006 - PublicProfile LogFileSize is adequate ($origValue)"
} else {
    netsh advfirewall set publicprofile logging maxfilesize 16384 | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242006 - Executed command: netsh advfirewall set publicprofile logging maxfilesize 16384"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 16384) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242006 - Correction validated; value updated to 16384"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242006 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 19 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242007"
    checkid     = "C-45282r698260_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242007"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
)
$property = "LogDroppedPackets"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242007 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242007 - Executed command: netsh advfirewall set allprofiles logging droppedconnections enable"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242007 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242007 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# ------------------- ROW 20 -------------------
$row = [PSCustomObject]@{
    Date        = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding     = "V-242008"
    checkid     = "C-45283r698263_chk"
    enabled     = $false
    corrected   = $false
    OrigValue   = $null
    Description = $descriptions["V-242008"]
}
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
)
$property = "LogSuccessfulConnections"
$origValue = Get-RegValue -Paths $regPaths -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 1) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242008 - No correction needed; value is $origValue"
} else {
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242008 - Executed command: netsh advfirewall set allprofiles logging allowedconnections enable"
    if (Validate-Setting -Paths $regPaths -PropertyName $property -ExpectedValue 1) {
        $row.corrected = $true
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242008 - Correction validated; value updated to 1"
    } else {
        $row.corrected = $false
        Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): V-242008 - Correction FAILED; value remains $origValue"
    }
}
$results += $row

# Export the results to CSV including the Description column
$results | Export-Csv -Path $csvPath -NoTypeInformation

# Log completion of script execution
Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Script completed. CSV saved to $csvPath"