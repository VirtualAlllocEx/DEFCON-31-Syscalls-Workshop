# Ensure the script is running with admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to have Administrator rights to run this script!`nPlease re-run this script as an Administrator."
    return
}

# Disable Real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Behavior Monitoring
Set-MpPreference -DisableBehaviorMonitoring $true

# Disable On-Access Protection
Set-MpPreference -DisableOnAccessProtection $true

# Disable Cloud-based Protection
Set-MpPreference -DisableIOAVProtection $true

# Disable Auto Sample Submission
Set-MpPreference -DisablePrivacyMode $true

# Disable Intrusion Prevention System
Set-MpPreference -DisableIntrusionPreventionSystem $true

# Disable Script Scanning
Set-MpPreference -DisableScriptScanning $true

# Disable Tamper Protection (Windows 10 1903 or later)
Set-MpPreference -DisableTamperProtection $true

Write-Output "Windows Defender features have been disabled."
