$VerbosePreference = "Continue"

function Download-CalderaFile($CalderaServer, $Name, $Dest){
    $EmptyBuffer = New-Object Byte[] 0
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("file",$Name)
    [byte[]] $FileContent = $wc.UploadData($CalderaServer + "/file/download", $EmptyBuffer)
    [io.file]::WriteAllBytes($Dest, $FileContent)
    return $true
}

function Install-Cagent($CalderaServer) {
    New-Item -ItemType directory -Path 'C:\Program Files\cagent' -Force
    If (Get-Service cagent -ErrorAction SilentlyContinue){
        Stop-Service cagent
    }
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($CalderaServer + '/conf.yml', 'C:\Program Files\cagent\conf.yml')
    $dl = $false
    While (-not $dl){
        trap {
            Write-Output 'Waiting for cagent.exe to unlock'
            Start-Sleep -s 2
        }
        $dl = Download-CalderaFile -CalderaServer $CalderaServer -Name cagent.exe -Dest 'C:\Program Files\cagent\cagent.exe'
    }
    If (Get-Service cagent -ErrorAction SilentlyContinue){
        Start-Service cagent
    } Else {
        New-Service -Name cagent -BinaryPathName 'C:\Program Files\cagent\cagent.exe' -DisplayName cagent -StartupType Automatic
        Start-Service cagent
    }
    Write-Output 'Cagent is Installed & Started'
}

# Optional: Disable SSL Verification
# Uncomment the following line to disable SSL verification. This can allow the installation to proceed
# if CALDERA is running using the development cert (in test environments only) or a self-signed cert that
# has not been added to the endpoint's Certificate Manager.
# [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# NOTE: Depending on how CALDERA is deployed, it may be necessary to edit the CalderaServer address below (use
# the base URL that allows you to navigate to the CALDERA WebUI from the endpoint https://<caldera host>:<caldera port>).
Install-Cagent -CalderaServer {{ url_root }}
