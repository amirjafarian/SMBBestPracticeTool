# Set the default sensitivity label on a SharePoint document library via SPO REST.
# Auth: OAuth 2.0 device-code flow against the SharePoint Online Management Shell
# client. Label discovery uses ExchangeOnlineManagement; pass -LabelGuid to skip it.
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        $uri = $null
        [Uri]::TryCreate($_, [UriKind]::Absolute, [ref]$uri) -and
        $uri.Scheme -eq 'https' -and
        $uri.Host -like '*.sharepoint.com'
    })]
    [string]$SiteUrl,

    [Parameter(Mandatory)]
    [ValidateScript({
        $guid = [Guid]::Empty
        [Guid]::TryParse($_, [ref]$guid)
    })]
    [string]$TenantId,

    [Parameter()]
    [ValidateScript({
        $guid = [Guid]::Empty
        [Guid]::TryParse($_, [ref]$guid)
    })]
    [string]$LabelGuid,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantAdminUpn,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LibraryTitle = 'Documents'
)

$ErrorActionPreference = 'Stop'

$siteUri = [Uri]$SiteUrl.TrimEnd('/')
$decodedPath = [Uri]::UnescapeDataString($siteUri.AbsolutePath).TrimEnd('/')
$lastPathSegment = Split-Path $decodedPath -Leaf
$knownLibrarySegments = @($LibraryTitle)
if ($LibraryTitle -eq 'Documents') { $knownLibrarySegments += 'Shared Documents' }

if ($lastPathSegment -in $knownLibrarySegments) {
    $siteUriBuilder = [UriBuilder]$siteUri
    $siteUriBuilder.Path = Split-Path $siteUri.AbsolutePath.TrimEnd('/') -Parent
    $normalizedSiteUrl = $siteUriBuilder.Uri.AbsoluteUri.TrimEnd('/')
    Write-Warning "SiteUrl points to the '$lastPathSegment' library. Using its owning site instead: $normalizedSiteUrl"
    $siteUrl = $normalizedSiteUrl
} else {
    $siteUrl = $SiteUrl.TrimEnd('/')
}

$tenantHost   = ([Uri]$siteUrl).Host                                # contoso.sharepoint.com

if (-not $LabelGuid) {
    $openedIppsSession = $false

    if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) {
        if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
            throw "Label discovery requires the ExchangeOnlineManagement module. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        }

        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $ippsArgs = @{ ShowBanner = $false }
        if ($TenantAdminUpn) { $ippsArgs['UserPrincipalName'] = $TenantAdminUpn }

        Write-Host 'Connecting to Security & Compliance to retrieve sensitivity labels...' -ForegroundColor Cyan
        Connect-IPPSSession @ippsArgs
        $openedIppsSession = $true
    }

    try {
        $allLabels = @(Get-Label -ErrorAction Stop)
        $labelOptions = @(
            foreach ($label in $allLabels) {
                if ($label.Mode -eq 'PendingDeletion' -or $label.Disabled -eq $true -or $label.IsLabelGroup -eq $true -or -not $label.Guid) {
                    continue
                }
                if ($label.ContentType -and [string]$label.ContentType -notmatch '(^|,\s*)File(\s*,|$)') {
                    continue
                }

                $displayPath = [string]$label.DisplayName
                if ($label.ParentId) {
                    $parent = $allLabels | Where-Object { $_.Guid -eq $label.ParentId } | Select-Object -First 1
                    if ($parent) { $displayPath = "$($parent.DisplayName) > $displayPath" }
                }

                [pscustomobject]@{
                    DisplayPath = $displayPath
                    Guid        = [string]$label.Guid
                }
            }
        ) | Sort-Object DisplayPath
    } finally {
        if ($openedIppsSession) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }

    if ($labelOptions.Count -eq 0) {
        throw 'No active, assignable sensitivity labels were found in the tenant.'
    }

    Write-Host "`nAvailable sensitivity labels:" -ForegroundColor Cyan
    for ($index = 0; $index -lt $labelOptions.Count; $index++) {
        Write-Host ('  [{0}] {1}' -f ($index + 1), $labelOptions[$index].DisplayPath)
    }

    $selectedNumber = 0
    do {
        $selection = Read-Host "Select a label (1-$($labelOptions.Count))"
        $validSelection = [int]::TryParse($selection, [ref]$selectedNumber) -and
            $selectedNumber -ge 1 -and $selectedNumber -le $labelOptions.Count
        if (-not $validSelection) { Write-Warning 'Enter one of the listed numbers.' }
    } until ($validSelection)

    $selectedLabel = $labelOptions[$selectedNumber - 1]
    $LabelGuid = $selectedLabel.Guid
    Write-Host "Selected '$($selectedLabel.DisplayPath)' ($LabelGuid)." -ForegroundColor Green
}

# Well-known first-party client trusted by SPO REST API.
$clientId = '9bc3ab49-b65d-410a-85ad-de819febfddc' # SharePoint Online Management Shell
$resource = "https://$tenantHost"

# Request a device code.
$device = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/devicecode" `
    -Body @{ client_id = $clientId; resource = $resource }

Write-Host $device.message -ForegroundColor Yellow

# Poll until the user completes sign-in.
$token = $null
$deadline = (Get-Date).AddSeconds([int]$device.expires_in)
while (-not $token -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds ([int]$device.interval)
    try {
        $response = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" `
            -Body @{
                grant_type = 'device_code'
                client_id  = $clientId
                code       = $device.device_code
            }
        $token = $response.access_token
    } catch {
        $tokenError = ($_.ErrorDetails.Message | ConvertFrom-Json).error
        if ($tokenError -ne 'authorization_pending' -and $tokenError -ne 'slow_down') { throw }
    }
}
if (-not $token) { throw 'Device-code sign-in timed out.' }


# 2. Get the form digest (required for write operations against /_api)
$digest = (Invoke-RestMethod -Method POST -Uri "$siteUrl/_api/contextinfo" -Headers @{
    Authorization = "Bearer $token"
    Accept        = "application/json;odata=verbose"
}).d.GetContextWebInformation.FormDigestValue

# 3. MERGE the list to set DefaultSensitivityLabelForLibrary
$body = @{
    __metadata                       = @{ type = "SP.List" }
    DefaultSensitivityLabelForLibrary = $labelGuid
} | ConvertTo-Json -Depth 4
$escapedLibraryTitle = $LibraryTitle.Replace("'", "''")
$listEndpoint = "$siteUrl/_api/web/lists/getbytitle('$escapedLibraryTitle')"

Invoke-RestMethod -Method POST -Uri $listEndpoint -Headers @{
    Authorization     = "Bearer $token"
    Accept            = "application/json;odata=verbose"
    "Content-Type"    = "application/json;odata=verbose"
    "X-RequestDigest" = $digest
    "X-HTTP-Method"   = "MERGE"
    "IF-MATCH"        = "*"
} -Body $body

# 4. Verify
(Invoke-RestMethod -Uri "${listEndpoint}?`$select=Title,DefaultSensitivityLabelForLibrary" -Headers @{
    Authorization = "Bearer $token"
    Accept        = "application/json;odata=verbose"
}).d | Select-Object Title, DefaultSensitivityLabelForLibrary
