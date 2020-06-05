[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Output expiring certificate within provided period')]
    $ExpiresInDays = 90,    
    [Parameter(HelpMessage = 'File where results will be outputed')]
    $OutputPath = "certificate_expiration_report_$(get-date -f yyyyMMdd).csv"
)
Write-Host "Script requires AzureAD module installed. Use 'Install-Module AzureAD -Scope CurrentUser' to install it for current user"
# Check if user is already authenticated - if not, execute Connect-AzureAd

if([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.Values -ne $null){
    Write-Host 'User already authenticated...'
}else{    
    Write-Host 'Authenticating to Azure AD...'
    Connect-AzureAD -ErrorAction Stop
    Write-Host 'Authenticated...'
}

Write-Host 'Gathering necessary information...'
$applications = Get-AzureADApplication -All 1
$servicePrincipals = Get-AzureADServicePrincipal

$appWithCredentials = @()
$appWithCredentials += $applications | Sort-Object -Property DisplayName | % {
    $application = $_    
    Write-Verbose ('Fetching information for application {0}' -f $application.DisplayName)
    $application | Get-AzureADApplicationKeyCredential -ErrorAction SilentlyContinue | Select-Object -Property @{Name='DisplayName'; Expression={$application.DisplayName}}, @{Name='ObjectId'; Expression={$application.ObjectId}}, @{Name='ApplicationId'; Expression={$application.AppId}}, @{Name='KeyId'; Expression={$_.KeyId}}, @{Name='Type'; Expression={$_.Type}},@{Name='StartDate'; Expression={$_.StartDate -as [datetime]}},@{Name='EndDate'; Expression={$_.EndDate -as [datetime]}}

  }

Write-Host 'Validating expiration data...'
$today = (Get-Date).ToUniversalTime()
$limitDate = $today.AddDays($ExpiresInDays)
$appWithCredentials | Sort-Object EndDate | % {
        if($_.EndDate -lt $today) {
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Expired'
        } elseif ($_.EndDate -le $limitDate) {
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'ExpiringSoon'
        } else {
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Valid'
        }       
}
$appWithCredentials | ? Status -NE "Valid" | Export-Csv -Path $OutputPath -NoTypeInformation -Delimiter ';'
Write-Host 'Done.'
