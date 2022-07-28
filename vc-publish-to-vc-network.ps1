<#
This script will allow you to publish your Verified ID contracts to the VC network
#>
param (
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$True)][string]$ClientId
)

##########################################################################################################
# just print the 70's style header
##########################################################################################################
function PrintMsg($msg) {
    $banner = "".PadLeft(78,"*")
    write-host "`n$banner`n* $msg`n$banner"
}

##########################################################################################################
# login to tenant using device code flow
##########################################################################################################
function Connect-AzADVCTenantViaDeviceFlow( 
        [Parameter(Mandatory=$True)][string]$ClientId,
        [Parameter(Mandatory=$True)][string]$TenantId,
        [Parameter()][string]$Scope = "6a8b4b39-c021-437c-b060-5a14a3fd65f3/full_access",                
        [Parameter(DontShow)][int]$Timeout = 300 # Timeout in seconds to wait for user to complete sign in process
)
{
    if ( !($Scope -imatch "offline_access") ) { $Scope += " offline_access"} # make sure we get a refresh token
    $retVal = $null
    try {
        $DeviceCodeRequest = Invoke-RestMethod -Method "POST" -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
                                                -Body @{ client_id=$ClientId; scope=$scope; } -ContentType "application/x-www-form-urlencoded"
        Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
        $url = $DeviceCodeRequest.verification_uri 
        Set-Clipboard -Value $DeviceCodeRequest.user_code
        if ( $env:PATH -imatch "/usr/bin" ) {
            $ret = [System.Diagnostics.Process]::Start("/usr/bin/open","$url")
        } else {
            $browser = (Get-ItemProperty HKCU:\Software\Microsoft\windows\Shell\Associations\UrlAssociations\http\UserChoice).ProgId
            $pgm = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
            $params = "-inprivate -new-window"
            switch( $browser.Replace("HTML", "").Replace("URL", "").ToLower() ) {        
                "firefox" { 
                    $pgm = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
                    $params = "-private -new-window"
                } 
                "chrome" { 
                    $pgm = "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe"
                    $params = "--incognito --new-window"
                } 
            }      
            $ret = [System.Diagnostics.Process]::Start($pgm,"$params $url")
        }
        $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
        while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
            if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
                throw 'Login timed out, please try again.'
            }
            $TokenRequest = try {
                Invoke-RestMethod -Method "POST" -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                                    -Body @{ grant_type="urn:ietf:params:oauth:grant-type:device_code"; code=$DeviceCodeRequest.device_code; client_id=$ClientId} `
                                    -ErrorAction Stop
            }
            catch {
                $Message = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($Message.error -ne "authorization_pending") {
                    throw
                }
            }
            Start-Sleep -Seconds 2
        }
        $retVal = $TokenRequest
    }
    finally {
        try {
            $TimeoutTimer.Stop()
        }
        catch {
            # We don't care about errors here
        }
    }
    $global:authHeader =@{ 'Content-Type'='application/json'; 'Authorization'=$retval.token_type + ' ' + $retval.access_token }
    #return $retval.access_token
}

##########################################################################################################
# Main script
##########################################################################################################

write-host "Signing in to Tenant $TenantId..."
Connect-AzADVCTenantViaDeviceFlow -TenantId $tenantId -ClientId $clientId

write-host "Getting Tenant Region..."
$tenantMetadata = invoke-restmethod -Uri "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
$baseUrl="https://beta.did.msidentity.com/$tenantID/api/portable/v1.0/admin"
if ( $tenantMetadata.tenant_region_scope -eq "EU" ) {
    $baseUrl = $baseUrl.Replace("https://beta.did", "https://beta.eu.did")
}

write-host "Retrieving VC Credential Contracts for tenant $tenantId..."
$contracts = Invoke-RestMethod -Method "GET" -Headers $global:authHeader -Uri "$baseUrl/contracts" -ErrorAction Stop

# enumerate all contracts 
foreach( $contract in $contracts ) {
    # only process new contracts that dont use Azure Storage for display & rules files
    if ( !($contract.rulesFile -and $contract.displayFile) ) {
        PrintMsg "$($contract.contractName) - already migrated from Azure Storage"
        
        write-host ($contract | ConvertTo-json -Depth 15 )
        
        $in = Read-host "$($contract.contractName) availableInVcDirectory=$($contract.availableInVcDirectory) - Want to publish this contract ? Yes (Y) or No(N)"

        if ($in -eq "Y")
        {
            $newContract = $contract;
     
            if ($contract.availableInVcDirectory -eq $false)
            {
                $newContract.availableInVcDirectory = $true

                # write-host "New Contract..."
                # write-host ($newContract | ConvertTo-json -Depth 15 )

                $in = Read-host "$($contract.contractName) - Go ahead with the update ? Yes (Y) or No(N)"

                if ($in -eq "Y")
                {
                    write-host "Updating Contract..."
                    $newContract = ($newContract | ConvertTo-json -Depth 15 -Compress)
                    Invoke-RestMethod -Method "PUT" -Uri "$baseUrl/contracts/$($contract.Id)" -Headers $global:authHeader -Body $newContract -ContentType "application/json" -ErrorAction Stop
                
                    PrintMsg "$($contract.contractName) - Successfully published to the VC network"
                }
            }
        }
    }
} # foreach
