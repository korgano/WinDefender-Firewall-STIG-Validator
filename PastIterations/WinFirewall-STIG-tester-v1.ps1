# Helper function to retrieve registry value from multiple paths
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

# Set paths for Desktop files
$desktop = [Environment]::GetFolderPath("Desktop")
$csvPath = Join-Path $desktop "WinFirewall-STIG-Checklist.csv"
$logFile = Join-Path $desktop "WinFirewall-STIG-actions.txt"

# Initialize log file (clear previous contents)
"" | Out-File -FilePath $logFile

# Array to hold CSV objects
$results = @()

# Row 1: V-241989, C-45264r921981_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241989"
    checkid  = "C-45264r921981_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 1 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles state on | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 1 - Corrected firewall state to on; original value was $origValue"
}
$results += $row

# Row 2: V-241990, C-45265r921984_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241990"
    checkid  = "C-45265r921984_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 2 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles state on | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 2 - Corrected firewall state to on; original value was $origValue"
}
$results += $row

# Row 3: V-241991, C-45266r921987_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241991"
    checkid  = "C-45266r921987_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 3 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles state on | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 3 - Corrected firewall state to on; original value was $origValue"
}
$results += $row

# Row 4: V-241992, C-45267r698215_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241992"
    checkid  = "C-45267r698215_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 4 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 4 - Corrected inbound action; original value was $origValue"
}
$results += $row

# Row 5: V-241993, C-45268r698218_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241993"
    checkid  = "C-45268r698218_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 5 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 5 - Corrected outbound action; original value was $origValue"
}
$results += $row

# Row 6: V-241994, C-45269r698221_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241994"
    checkid  = "C-45269r698221_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 6 - LogFileSize is adequate ($origValue)"
} else {
    $row.enabled = $false
    netsh advfirewall set domainprofile logging maxfilesize 16384 | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 6 - Corrected LogFileSize to 16384; original value was $origValue"
}
$results += $row

# Row 7: V-241995, C-45270r698224_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241995"
    checkid  = "C-45270r698224_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 7 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 7 - Corrected dropped connections logging; original value was $origValue"
}
$results += $row

# Row 8: V-241996, C-45271r698227_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241996"
    checkid  = "C-45271r698227_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 8 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 8 - Corrected allowed connections logging; original value was $origValue"
}
$results += $row

# Row 9: V-241997, C-45272r698230_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241997"
    checkid  = "C-45272r698230_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 9 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 9 - Corrected standard profile inbound action; original value was $origValue"
}
$results += $row

# Row 10: V-241998, C-45273r698233_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241998"
    checkid  = "C-45273r698233_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 10 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 10 - Corrected standard profile outbound action; original value was $origValue"
}
$results += $row

# Row 11: V-241999, C-45274r698236_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-241999"
    checkid  = "C-45274r698236_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 11 - LogFileSize is adequate ($origValue)"
} else {
    $row.enabled = $false
    netsh advfirewall set privateprofile logging maxfilesize 16384 | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 11 - Corrected PrivateProfile LogFileSize to 16384; original value was $origValue"
}
$results += $row

# Row 12: V-242000, C-45275r698239_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242000"
    checkid  = "C-45275r698239_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 12 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 12 - Corrected dropped connections logging for PrivateProfile; original value was $origValue"
}
$results += $row

# Row 13: V-242001, C-45276r698242_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242001"
    checkid  = "C-45276r698242_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 13 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 13 - Corrected allowed connections logging for PrivateProfile; original value was $origValue"
}
$results += $row

# Row 14: V-242002, C-45277r698245_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242002"
    checkid  = "C-45277r698245_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 14 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 14 - Corrected PublicProfile inbound action; original value was $origValue"
}
$results += $row

# Row 15: V-242003, C-45278r698248_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242003"
    checkid  = "C-45278r698248_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 15 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 15 - Corrected PublicProfile outbound action; original value was $origValue"
}
$results += $row

# Row 16: V-242004, C-45279r698251_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242004"
    checkid  = "C-45279r698251_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
}
# Only one registry path for AllowLocalPolicyMerge
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$property = "AllowLocalPolicyMerge"
$origValue = Get-RegValue -Paths @($regPath) -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 16 - AllowLocalPolicyMerge is 0; no correction needed"
} else {
    $row.enabled = $false
    # No command executed per instructions
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 16 - AllowLocalPolicyMerge is not 0; no correction executed"
}
$results += $row

# Row 17: V-242005, C-45280r698254_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242005"
    checkid  = "C-45280r698254_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
}
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$property = "AllowLocalIPsecPolicyMerge"
$origValue = Get-RegValue -Paths @($regPath) -PropertyName $property
$row.OrigValue = $origValue

if ($origValue -eq 0) {
    $row.enabled = $true
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 17 - AllowLocalIPsecPolicyMerge is 0; no correction needed"
} else {
    $row.enabled = $false
    # No command executed per instructions
    $row.corrected = $false
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 17 - AllowLocalIPsecPolicyMerge is not 0; no correction executed"
}
$results += $row

# Row 18: V-242006, C-45281r698257_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242006"
    checkid  = "C-45281r698257_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 18 - PublicProfile LogFileSize is adequate ($origValue)"
} else {
    $row.enabled = $false
    netsh advfirewall set publicprofile logging maxfilesize 16384 | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 18 - Corrected PublicProfile LogFileSize to 16384; original value was $origValue"
}
$results += $row

# Row 19: V-242007, C-45282r698260_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242007"
    checkid  = "C-45282r698260_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 19 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 19 - Corrected PublicProfile dropped packets logging; original value was $origValue"
}
$results += $row

# Row 20: V-242008, C-45283r698263_chk
$row = [PSCustomObject]@{
    Date     = (Get-Date -Format "MM-dd-yyyy HH:mm")
    Finding  = "V-242008"
    checkid  = "C-45283r698263_chk"
    enabled  = $false
    corrected= $false
    OrigValue= $null
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
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 20 - No correction needed; value is $origValue"
} else {
    $row.enabled = $false
    netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
    $row.corrected = $true
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Row 20 - Corrected PublicProfile allowed connections logging; original value was $origValue"
}
$results += $row

# Export the results to CSV
$results | Export-Csv -Path $csvPath -NoTypeInformation

# Log completion
Add-Content -Path $logFile -Value "$(Get-Date -Format 'MM-dd-yyyy HH:mm'): Script completed. CSV saved to $csvPath"
