# CALDERA plugin: Adversary

This plugin contains:
* The original CALDERA mode in plugin form
* This includes multiple REST API endpoints, an agent and a RAT and a GUI component. 

This plugin will allow you to run operations on Windows hosts only.

## Requirements

To use this plugin, you must have a Mongo database installed and running locally.
Detailed MongoDB Server installation instructions can be found here: 
https://docs.mongodb.com/manual/installation/#mongodb-community-edition-installation-tutorials

This plugin also requires that you load the GUI plugin with it.

## BSF

Operations run through the Adversary Plugin generate logs in the BRAWL Shared Format (BSF). More information about 
this format can be found <a href="https://github.com/mitre/brawl-public-game-001#bsf">here</a>. Please note 
that CALDERA's BSF download produces an ordered collection of BSF objects (other header information, such as 'game_id' 
and 'bsf_version', is handled elsewhere). Excerpts from an example CALDERA generated BSF log are documented here as an 
example of how to read and reference the format.
```
[
    {
        "id": "b083958c-e052-4c04-b466-1cab8a4d819e",           # Entry ID 
        "nodetype": "event",                                    # Entry Type (BSF event)
        "host": "dc.caldera.local",                             # The host involved
        "object": "process",                                    # What was involved
        "action": "create",                                     # What happened
        "happened_after": "2019-03-04T21:12:24.575720+00:00",   # When did the event occur (start)
        "fqdn": "dc.caldera.local",                             # FQDN of the host
        "ppid": 2968,                                           # PPID involved
        "pid": 2596,                                            # PID involved
        "command_line": "powershell -command -",                # commandline captured
        "happened_before": "2019-03-04T21:12:29.480753+00:00"   # When did the event occur (end)
    },                                                          #
    {                                                           #
        "id": "ee802ac0-e757-4a81-80ea-ea294eb47f6b",           # Entry ID 
        "nodetype": "step",                                     # Entry Type ('step' is a CALDERA step)
        "attack_info": [                                        # Step ATT&CK taxonomy information
            {                                                   #
                "technique_id": "T1018",                        # Associated technqiue ID
                "technique_name": "Remote System Discovery",    # Associated technique Name
                "tactic": [                                     # Associated tactics
                    "Discovery"                                 #
                ]                                               #
            },                                                  #
            {                                                   #
                "technique_id": "T1086",                        #
                "technique_name": "PowerShell",                 #
                "tactic": [                                     #
                    "Execution"                                 #
                ]                                               #
            },                                                  #
            {                                                   #
                "technique_id": "T1064",                        #
                "technique_name": "Scripting",                  #
                "tactic": [                                     #
                    "Defense Evasion",                          #
                    "Execution"                                 #
                ]                                               #
            },                                                  #
            {                                                   #
                "technique_id": "T1106",                        #
                "technique_name": "Execution through API",      #
                "tactic": [                                     #
                    "Execution"                                 #
                ]                                               #
            }                                                   #
        ],                                                      #
        "events": [                                             #
            "b083958c-e052-4c04-b466-1cab8a4d819e"              # Associated step event
        ],
        "key_technique": "T1018",                               # Primary technique involved
        "key_event": "b083958c-e052-4c04-b466-1cab8a4d819e",    # Primary event associated
        "host": "dc.caldera.local",                             # Host involved
        "time": "2019-03-04T21:12:27.028237+00:00",             # Time step occured
        "description": "Enumerating all computers in the domain"# Step description
    },                                                          #
    ...                                                         #
    {                                                           #
        "id": "8bedb0b2-b566-4a5b-9b0a-f24c81a262cd",           # Entry ID
        "steps": [                                              # Entry Associated Steps
            "ee802ac0-e757-4a81-80ea-ea294eb47f6b",             #
            "3c9395ae-71f5-4109-94cb-1cc3ca0b6cdb",             #
            "1a5584c3-4081-4922-b957-e2e1b32b1180",             #
            "b3223370-30d7-4484-a18e-d6668bf8d11e",             #
            "9934276d-968c-4584-9e37-c1d81e7c0753",             #
            "db1e2188-5c9b-4ca1-aef5-c9e0d2ce415b",             #
            "f5598a0d-6c0e-4766-9a8f-c25f69e2270b",             #
            "0aa4f283-aa07-4024-9544-e64644e5bcc6",             #
            "bbe654be-edc8-4823-83e6-908380abb1e5",             #
            "d218c2aa-50ef-483c-b63a-33e1fcbee459",             #
            "330526e2-7a15-42b8-9f9c-9bc1ab30a1ad",             #
            "1d11a093-c4eb-4388-865a-b1c4c83e5152",             #
            "a196bad2-8310-4bc7-b5a6-e85b6a60e110",             #
            "2390973a-0afe-4206-8179-6bed0e8d6651"              #   
        ],                                                      #
        "nodetype": "operation"                                 # Entry Type (CALDERA Operation)
    }
]
```

## Host Softening

In order for Adversary Mode to move laterally through the network and successfully leverage PowerSploit tools, several 
security features of Windows 10 must be turned off. We have provided a simple powershell script below to disable those
features; it has been tested on Windows 10 (up to 1904) and Server 2012. This script will do a couple things:
* Disable credential protections and enable clear text caching
* Open RPC and SMB firewall ports
* Create an exploitable service for privilege escalation
* Seed flags for exfiltration
* Enable remote SAM access for Users

### Prerequisites
* Administrator or NT AUTHORITY/SYSTEM privileges
* Powershell

### Usage Instructions
1. Save the below script as a .ps1 file (soften.ps1)
2. Open an Administrator powershell session
3. Execute the script (./soften.ps1)

### Disclaimer
This script has been tested on limited Windows distributions (but it *should* work on most versions). **THIS WILL DISABLE
CRITICAL SECURITY FEATURES ON WINDOWS - USE AT YOUR OWN RISK.**

```powershell
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "You must run this script as Administrator or NT_AUTHORITY/SYSTEM"
}

# Set execution policy bypass policy for local machine
function executionBypass{
    Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Bypass -Force
}

# Disable Virtualization Based Security (Disable Credential Guard)
function disableCredGuard{
    reg add hklm\SYSTEM\CurrentControlSet\Control\DeviceGuard\ /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
}

# Turn on Plain-Text Credential Caching
function plainTextCredCaching{
    reg add hklm\SYSTEM\CurrentControlSet\Control\DeviceGuard\ /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
}

# Allow SMB in Host Firewall
function smbFirewall{
    Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
}

# Allow RPC in Host Firewall
function rpcFirewall{
    Enable-NetFirewallRule -DisplayName "Remote Scheduled Tasks Management (RPC)"
}

# start exploitable service
function createExploitableService{
    $svcname = "badpanda"
    $folder = "C:\badservice"
    if(!(Test-Path -Path $folder)){md $folder}
    $acl = Get-Acl $folder
    $ar_users = New-Object System.Security.AccessControl.FileSystemAccessRule('Users','FullControl','Allow')
    $acl.SetAccessRule($ar_users)
    Set-Acl $folder $acl
    Copy-Item -Path "C:\Windows\System32\snmptrap.exe" -Destination "$folder\$svcname.exe"
    if(Get-Service -name $svcname -ErrorAction SilentlyContinue){
        Stop-Service -Name $svcname -Force
        (Get-Service -name $svcname).WaitForStatus("Stopped")
        sc.exe delete $svcname
    }
    New-Service -Name $svcname -BinaryPathName "$folder\$svcname.exe" -StartupType Automatic
    Start-Process -NoNewWindow -FilePath "powershell.exe" -ArgumentList "Start-Service $svcname"
    sc.exe sdset $svcname 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BU)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
}

# seed randomized flag files for exfil
function seedFlags{
    $usrroot = "C:\Users"
    [Array]$usraccts = Get-ChildItem "$usrroot" -Exclude "Public" | %{@{Path=$_.FullName}}
    foreach($acct in $usraccts){
        $rand=Get-Random -Minimum 1 -Maximum 3
        $flag= -join ((33..90)+(97..122) | Get-Random -Count 25 | % {[char]$_})
        if($rand -eq 1){$fileName="\password_file.txt"}else{$fileName='\admin_information.txt'}
        $file = Join-Path $acct.Values $fileName
        New-Item -ItemType "file" -Path $file -Value "Flag: $flag" -Force | Out-Null
    }
}

# Enable Remote SAM access for the 'Users' group.  By default on Windows 10 1607+ this is restricted
# to Local Administrators. This change allows CALDERA to remotely enumerate the local admin group of
# this machine. For more information about this setting see: 
# https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
function enableRemoteSAM{
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictRemoteSam -Value "O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;BU)" 
}

# TODO: Flag for restart or reboot host?
function rebootHost{
    Restart-Computer -Force
}

$tasks = @(
    (Get-Item function:executionBypass),
    (Get-Item function:disableCredGuard),
    (Get-Item function:plainTextCredCaching),
    (Get-Item function:smbFirewall),
    (Get-Item function:rpcFirewall),
    (Get-Item function:createExploitableService),
    (Get-Item function:seedFlags),
    (Get-Item function:enableRemoteSAM),
    (Get-Item function:rebootHost)
)
$actionText = @(
    "Setting Execution policy to BYPASS...",
    "Disable Virtualization Based Security (Disable Credential Guard)...",
    "Turn on Plain-Text Credential Caching...",
    "Allow SMB through the host firewall...",
    "Allow RPC through the host firewall...",
    "Building and starting an exploitable service...",
    "Seed flags in User folders...",
    "Allowing 'Users' remote SAM access",
    "Rebooting host..."
)

function updateProgress{
    param($index, $total, $actionText)
    $text = "Action $($index.ToString().PadLeft($total.Count.ToString().Length)) of $total | " + $actionText
    $block = [scriptblock]::Create($text)
    Write-Progress -Id 1 -Activity "Softening host..." -Status ($block) -PercentComplete ($index/$total*100)
}

$totalTasks = $tasks.Length
for($i=1; $i -le ($totalTasks); $i++){
    updateProgress $i $totalTasks $actionText[$i-1]
    & $tasks[$i-1]
    start-sleep -s 1
}
```