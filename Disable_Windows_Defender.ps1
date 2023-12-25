# Ensure the script is running with admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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
# Note: This might not work as expected since Tamper Protection is designed to prevent unauthorized changes
# You might need to disable it manually through the Windows Security app, especially in newer versions of Windows 10
Set-MpPreference -DisableTamperProtection $true
