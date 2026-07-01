<#
.SYNOPSIS
    This PowerShell script disables Bluetooth on Windows 11 via the Bluetooth CSP policy registry key.
.NOTES
    Author          : Mohamed Yagoub
    LinkedIn        : linkedin.com/in/mohamed-yagoub/
    GitHub          : github.com/goubx
    Date Created    : 2026-06-29
    Last Modified   : 2026-06-29
    Version         : 1.2
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000210
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-00-000210/
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 
.USAGE
    Run this script in an elevated PowerShell session on the target Windows 11 host.
    Note: This STIG is N/A if the system has no Bluetooth radio.
    After execution, run 'gpupdate /force' and rescan with Tenable Nessus to validate.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-00-000210).ps1
#>

# STIG WN11-00-000210: Bluetooth must be turned off unless approved by the organization
$RegPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity'
$Name    = 'AllowBluetooth'
$Desired = 0   # 0 = Bluetooth disabled (Bluetooth CSP)

# Create the registry path if it does not exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
    Write-Host "Created registry path: $RegPath"
}

# Apply the AllowBluetooth value
Set-ItemProperty -Path $RegPath -Name $Name -Value $Desired -Type DWord -Force
Write-Host "Set $Name to $Desired in $RegPath"

# Verify
$Current = (Get-ItemProperty -Path $RegPath -Name $Name).$Name
if ($Current -eq $Desired) {
    Write-Host "Compliant: $Name = $Current"
} else {
    Write-Warning "Non-compliant: $Name = $Current, expected $Desired"
}
