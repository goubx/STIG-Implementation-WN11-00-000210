# STIG-Implementation-WN11-00-000210

## Intial Scan results

Intial scan results show that over 144 audits failed out of 263.

[image]

the failed audit i will be remediating is:

> WN11-00-000210 - Bluetooth must be turned off unless approved by the organization.

[image]

Enforcing this policy is critical within an enterprise environment to reduce the attack surface. Restricting Bluetooth by default ensures that unapproved or insecure wireless devices cannot establish unauthorized connections with corporate assets.

## Researching the stig ID

After researching the STIG ID, I discovered the necessary information to begin the remediation process on stigviewer.com

the check per disa is:

```
Check Text (C-253291r1153422_chk)
This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity\

Value Name: AllowBluetooth

Value Type: REG_DWORD
Value: 0x00000000 (0)

Approval must be documented with the ISSO.
```

and the fix per disa is:

```
Fix Text (F-56694r1153421_fix)
Turn off Bluetooth radios not organizationally approved.

For systems managed by Intune, apply the DOD Windows 11 STIG Settings Catalog (or equivalent Intune policy) found in the Intune policy package available on cyber.mil.
Steps to create an Intune policy:
1. Sign in to the Intune admin center >> Devices >> Configuration >> Create >> New Policy.
2. Platform: Windows 10 and later. Profile type: Settings Catalog, then click "Create".
3. Basics: Provide a Name and Description of the profile, then click "Next".
4. Configuration settings: Click "+ Add settings" and search for connectivity under the Settings picker. Under the Connectivity category, check the box next to Allow Bluetooth setting. Choose the first option, "Disallow Bluetooth", then click "Next".
5. Scope tags: (optional), then click "Next".
6. Assignments: Assign the policy to Entra security groups that contain the target users or devices, then click "Next".
7. Review + create: Review the deployment summary, then click "Create".
```

# Begin manual remeditation

First I will investigate the Registry Editor, to confirm that the correct path does not exist and the vulnerablity is present.

[image]

After reviewing the registry editor, i was able to confirm that the correct path does not exist. vulnerablity is present.

I will now begin the fix and will later on confirm within the registry if the correct path appears.

**** After doing some research, I have discovered that the VM does not have Intune Policy available. I will attempt to remediate this through the reguistry editor by creating the correct path.

[image]

As explained above, I have created the correct path within registry editor as per the STIG. 

## I will now run a scan and see if this STIG passes the audit scan

[image] 

After running the scan my manual remediation was successful and the audit has passed. I will now remove any manual work I did, and rescan to confirm it was removed successfully.

## Post manual remediation removal scan

[image]

As you can see my manual remediation was successfully removed, and now i can being with the pragmatic remediation.

## Pragmatic Remediation

Below is the PowerShell Script I have curated per DISA.

```powershell
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
```

[image]

I will now begin another scan to confirm the pragmatic remediation was successful.

## Post pragmatic remediation scan 

[image]

As expected, the pragmatic remediation was successful in getting a success on the audit scan.






