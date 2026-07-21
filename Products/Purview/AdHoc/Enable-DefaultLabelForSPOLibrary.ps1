# Set the default sensitivity label on a SharePoint document library via SPO REST.
# Auth: OAuth 2.0 device-code flow against the SharePoint Online Management Shell client
# (pre-consented for SPO in every tenant). No PnP, no MSAL, no Az modules required.
$siteUrl      = "https://contoso.sharepoint.com/sites/test"
$tenantHost   = ([Uri]$siteUrl).Host                                # contoso.sharepoint.com
$tenantId     = "<your-tenant-id-guid>"
$libraryTitle = "Documents"
$labelGuid    = "<your-sensitivity-label-guid>"

# Well-known first-party client trusted by SPO REST API
$clientId = "9bc3ab49-b65d-410a-85ad-de819febfddc"   # SharePoint Online Management Shell
$resource = "https://$tenantHost"

# 1a. Request a device code
$device = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/devicecode" `
    -Body @{ client_id = $clientId; resource = $resource }

Write-Host $device.message -ForegroundColor Yellow

# 1b. Poll the token endpoint until the user finishes signing in
$token = $null
$deadline = (Get-Date).AddSeconds([int]$device.expires_in)
while (-not $token -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds ([int]$device.interval)
    try {
        $resp = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" `
            -Body @{
                grant_type = "device_code"
                client_id  = $clientId
                code       = $device.device_code
            }
        $token = $resp.access_token
    } catch {
        $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error
        if ($err -ne "authorization_pending" -and $err -ne "slow_down") { throw }
    }
}
if (-not $token) { throw "Device-code sign-in timed out." }


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

Invoke-RestMethod -Method POST -Uri "$siteUrl/_api/web/lists/getbytitle('$libraryTitle')" -Headers @{
    Authorization     = "Bearer $token"
    Accept            = "application/json;odata=verbose"
    "Content-Type"    = "application/json;odata=verbose"
    "X-RequestDigest" = $digest
    "X-HTTP-Method"   = "MERGE"
    "IF-MATCH"        = "*"
} -Body $body

# 4. Verify
(Invoke-RestMethod -Uri "$siteUrl/_api/web/lists/getbytitle('$libraryTitle')?`$select=Title,DefaultSensitivityLabelForLibrary" -Headers @{
    Authorization = "Bearer $token"
    Accept        = "application/json;odata=verbose"
}).d | Select-Object Title, DefaultSensitivityLabelForLibrary
