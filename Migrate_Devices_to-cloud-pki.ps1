#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

# Version 5: keeps contextual emoji, colored console logging, throttling-safe
# Intune export polling, continuous 30-second cycles, and device sync.
# Persistent CSV log/report creation has been removed.

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Microsoft Graph app-only authentication using an Entra application client secret.
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ClientId,

    # Use the client secret VALUE from Entra ID (not the Secret ID).
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientSecret,

    # Step 1: devices with the Cloud PKI SCEP certificate profile are added here.
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$Step1SourceGroupId = '4b339bd0-2b5a-467c-a945-a8491dfc4fd1',

    # Step 2: devices waiting for both 802.1X profiles to succeed.
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$Step2GroupId = 'da6690b8-de59-4953-a058-185d76330236',

    # Step 3: devices where both 802.1X profiles succeeded.
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$Step3GroupId = '7ddc27aa-f69f-4e82-aae9-d463fd40b852',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CertificatePolicyName = 'CLOUDPKI-FAIRSTONE-SCEP',

    [Parameter()]
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string]$CertificatePolicyId = '',

    [Parameter()]
    [string[]]$AcceptedCertificateStatuses = @(
        'Issued',
        'Active',
        'Valid',
        'Succeeded'
    ),

    [Parameter()]
    [switch]$IncludeExpiredCertificates,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WiredPolicyName = 'ALL - System - Wired - Configuration (CLOUDPKI)',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WirelessPolicyName = 'ALL - System - Wifi - Configuration (CLOUDPKI)',

    [Parameter()]
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string]$WiredPolicyId = '',

    [Parameter()]
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')]
    [string]$WirelessPolicyId = '',

    [Parameter()]
    [string[]]$AcceptedPolicyStatuses = @(
        'Succeeded',
        'Success',
        'Compliant',
        'Remediated'
    ),

    # Disabled by default because the tenant-wide Policies export can
    # intermittently return HTTP 500. Enable only when direct policy lookup fails.
    [Parameter()]
    [switch]$UsePoliciesReportFallback,

    [Parameter()]
    [switch]$UseTransitiveStep1SourceMembers,

    [Parameter()]
    [switch]$UseTransitiveStep2Members,

    # Used only when collecting the Step 3 devices for the final sync phase.
    [Parameter()]
    [switch]$UseTransitiveStep3Members,

    # By default, the script triggers an Intune sync for every unique device
    # found across the Step 1, Step 2, and Step 3 migration groups.
    [Parameter()]
    [switch]$SkipDeviceSync,

    # Small delay between sync requests to reduce Microsoft Graph throttling.
    [Parameter()]
    [ValidateRange(0, 5000)]
    [int]$SyncDelayMilliseconds = 250,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$ReportTimeoutMinutes = 20,

    [Parameter()]
    # Intune exportJobs allows only a limited number of requests per user per
    # minute. Polling faster than 10 seconds can exceed that limit, especially
    # when a fallback status URI is also queried.
    [ValidateRange(10, 120)]
    [int]$ReportPollSeconds = 15,

    # By default, the complete migration workflow runs again after this delay.
    # Use -RunOnce to execute only one cycle.
    [Parameter()]
    [ValidateRange(1, 86400)]
    [int]$RepeatDelaySeconds = 30,

    [Parameter()]
    [switch]$RunOnce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure emoji and other Unicode characters display correctly in modern
# PowerShell terminals. Unsupported legacy consoles may show monochrome symbols.
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
}
catch {
    # Logging still works if the host doesn't allow changing its encoding.
}

function Get-LogEmoji {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    # Context-specific emoji take priority over the generic log-level icon.
    switch -Regex ($Message) {
        '(?i)starting migration cycle|cycle \d+ finished|next cycle'            { return '🔁' }
        '(?i)connecting to Microsoft Graph|connected as'                         { return '🔐' }
        '(?i)resolved policy|policy ID|policy lookup'                            { return '🛡️' }
        '(?i)export job|export status|downloading Intune report|imported .*row'  { return '📊' }
        '(?i)starting Step 1|certificate validation|eligible certificate'        { return '🪪' }
        '(?i)starting Step 2|802\.1X|wired|wireless|profile validation'         { return '📡' }
        '(?i)sync requested|device sync|synchroniz|sync phase'                   { return '🔄' }
        '(?i)source group|Step 2 group|Step 3 group|device member'               { return '👥' }
        '(?i)retrieving Intune managed devices|Intune managed device'            { return '💻' }
        '(?i)sleeping|waiting .*seconds'                                         { return '😴' }
    }

    switch ($Level) {
        'SUCCESS' { return '✅' }
        'WARN'    { return '⚠️' }
        'ERROR'   { return '❌' }
        default   { return 'ℹ️' }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = Get-Date -Format 'HH:mm:ss'
    $emoji = Get-LogEmoji -Level $Level -Message $Message

    # Presentation only: this function intentionally changes no script logic.
    # It uses separate Write-Host segments so timestamps, badges, context and
    # messages can have different colors while keeping the same log content.
    $levelStyle = switch ($Level) {
        'SUCCESS' {
            @{
                Foreground = 'Black'
                Background = 'Green'
                TextColor  = 'Green'
                Label      = ' OK '
            }
        }
        'WARN' {
            @{
                Foreground = 'Black'
                Background = 'Yellow'
                TextColor  = 'Yellow'
                Label      = ' WARN '
            }
        }
        'ERROR' {
            @{
                Foreground = 'White'
                Background = 'DarkRed'
                TextColor  = 'Red'
                Label      = ' ERROR '
            }
        }
        default {
            @{
                Foreground = 'Black'
                Background = 'Cyan'
                TextColor  = 'Cyan'
                Label      = ' INFO '
            }
        }
    }

    # Give major workflow milestones a little visual breathing room.
    $isSectionStart = $Message -match '(?i)^Starting (migration cycle|Step 1:|Step 2:|device sync)'
    $isCycleEnd = $Message -match '(?i)^Cycle \d+ finished\.'
    $isSummary = $Message -match '(?i)^(Step 1 completed\.|Step 2 completed\.|Device sync completed\.)'

    if ($isSectionStart) {
        Write-Host ''
        Write-Host ((('─' * 92) -join '')) -ForegroundColor DarkGray
    }

    # Timestamp
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray

    # Colored level badge
    Write-Host $levelStyle.Label `
        -NoNewline `
        -ForegroundColor $levelStyle.Foreground `
        -BackgroundColor $levelStyle.Background

    # Context emoji + message
    Write-Host " $emoji " -NoNewline -ForegroundColor $levelStyle.TextColor
    Write-Host $Message -ForegroundColor $levelStyle.TextColor

    if ($isSummary -or $isCycleEnd) {
        Write-Host ((('─' * 92) -join '')) -ForegroundColor DarkGray
    }
}

function Get-ObjectValue {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Get-GraphHttpStatusCode {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $statusCode = $null

    if ($ErrorRecord.Exception.PSObject.Properties['ResponseStatusCode']) {
        try { $statusCode = [int]$ErrorRecord.Exception.ResponseStatusCode } catch { }
    }
    elseif ($ErrorRecord.Exception.PSObject.Properties['Response'] -and $ErrorRecord.Exception.Response) {
        try { $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode } catch { }
    }

    if ($null -eq $statusCode) {
        $errorDetailsText = if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message } else { '' }
        $errorText = @([string]$ErrorRecord.Exception.Message, $errorDetailsText) -join ' '

        if ($errorText -match '(?i)\bHTTP(?:/\d(?:\.\d)?)?\s+(\d{3})\b') {
            $statusCode = [int]$Matches[1]
        }
        elseif ($errorText -match '(?i)\b(404|408|429|500|502|503|504)\b') {
            $statusCode = [int]$Matches[1]
        }
        elseif ($errorText -match '(?i)NotFound|Not Found') {
            $statusCode = 404
        }
    }

    return $statusCode
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$MaxAttempts = 6,

        # Use only for resources that can briefly return 404 while being
        # replicated across Microsoft Graph/Intune report back-end instances.
        [Parameter()]
        [switch]$TreatNotFoundAsTransient
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $params = @{
                Method      = $Method
                Uri         = $Uri
                ErrorAction = 'Stop'
            }

            if ($null -ne $Body) {
                $params.Body = if ($Body -is [string]) {
                    $Body
                }
                else {
                    $Body | ConvertTo-Json -Depth 10 -Compress
                }
                $params.ContentType = 'application/json'
            }

            if ($Headers) {
                $params.Headers = $Headers
            }

            return Invoke-MgGraphRequest @params
        }
        catch {
            $errorDetailsText = if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' }
            $errorText = @([string]$_.Exception.Message, $errorDetailsText) -join ' '
            $statusCode = Get-GraphHttpStatusCode -ErrorRecord $_

            $transientStatusCodes = @(408, 429, 500, 502, 503, 504)
            if ($TreatNotFoundAsTransient) {
                $transientStatusCodes += 404
            }

            $isTransientStatus = $statusCode -in $transientStatusCodes
            $isTransientText = $errorText -match '(?i)(408|429|500|502|503|504|Too Many Requests|Internal Server Error|temporarily unavailable|timeout|timed out)'
            if ($TreatNotFoundAsTransient -and $errorText -match '(?i)(404|NotFound|Not Found)') {
                $isTransientText = $true
            }

            $isTransient = $isTransientStatus -or $isTransientText

            if (-not $isTransient -or $attempt -eq $MaxAttempts) {
                throw
            }

            $baseDelay = [Math]::Min(60, [Math]::Pow(2, $attempt))
            $jitter = Get-Random -Minimum 0 -Maximum 3
            $delay = [int]($baseDelay + $jitter)
            $statusText = if ($null -ne $statusCode) { " HTTP $statusCode" } else { '' }
            Write-Log -Level WARN -Message "Transient Graph error$statusText. Retrying in $delay seconds. Attempt $attempt of $MaxAttempts."
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphCollection {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    while (-not [string]::IsNullOrWhiteSpace([string]$nextLink)) {
        $response = Invoke-GraphRequestWithRetry -Method GET -Uri $nextLink -Headers $Headers

        $responseItems = Get-ObjectValue -InputObject $response -Name 'value'
        if ($null -ne $responseItems) {
            foreach ($item in @($responseItems)) {
                $items.Add($item)
            }
        }

        $nextLink = Get-ObjectValue -InputObject $response -Name '@odata.nextLink'
    }

    return $items.ToArray()
}

function Get-GroupDetails {
    param(
        [Parameter(Mandatory)]
        [string]$GroupId
    )

    $uri = "https://graph.microsoft.com/v1.0/groups/${GroupId}?`$select=id,displayName,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState"
    return Invoke-GraphRequestWithRetry -Method GET -Uri $uri
}

function Assert-StaticSecurityGroup {
    param(
        [Parameter(Mandatory)]
        [object]$Group,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    $displayName = [string](Get-ObjectValue -InputObject $Group -Name 'displayName')
    $securityEnabled = [bool](Get-ObjectValue -InputObject $Group -Name 'securityEnabled')
    $groupTypes = @(Get-ObjectValue -InputObject $Group -Name 'groupTypes')

    if (-not $securityEnabled) {
        throw "$Purpose group '$displayName' is not a security group. Entra devices cannot be manually added to a Microsoft 365 group."
    }

    if ($groupTypes -contains 'DynamicMembership') {
        throw "$Purpose group '$displayName' uses dynamic membership. Devices cannot be manually added to a dynamic group."
    }
}

function Get-GroupDeviceMembers {
    param(
        [Parameter(Mandatory)]
        [string]$GroupId,

        [Parameter()]
        [switch]$Transitive
    )

    $relationship = if ($Transitive) { 'transitiveMembers' } else { 'members' }
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/$relationship/microsoft.graph.device?`$select=id,deviceId,displayName&`$count=true&`$top=999"
    $headers = @{ ConsistencyLevel = 'eventual' }

    return @(Get-GraphCollection -Uri $uri -Headers $headers)
}

function Normalize-PolicyName {
    param([object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    $normalized = [string]$Value
    $normalized = $normalized.Replace([char]0x00A0, ' ')
    $normalized = $normalized.Replace([char]0x2010, '-')
    $normalized = $normalized.Replace([char]0x2011, '-')
    $normalized = $normalized.Replace([char]0x2012, '-')
    $normalized = $normalized.Replace([char]0x2013, '-')
    $normalized = $normalized.Replace([char]0x2014, '-')
    $normalized = $normalized.Replace([char]0x2212, '-')
    $normalized = [regex]::Replace($normalized, '\s+', ' ').Trim()

    return $normalized
}

function ConvertTo-DateTimeOffsetOrNull {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function Export-IntuneReport {
    param(
        [Parameter(Mandatory)]
        [string]$ReportName,

        [Parameter(Mandatory)]
        [string[]]$Select,

        [Parameter()]
        [string]$Filter,

        [Parameter(Mandatory)]
        [int]$TimeoutMinutes,

        [Parameter(Mandatory)]
        [int]$PollSeconds
    )

    $body = @{
        reportName       = $ReportName
        format           = 'csv'
        select           = $Select
        localizationType = 'replaceLocalizableValues'
    }

    if (-not [string]::IsNullOrWhiteSpace($Filter)) {
        $body.filter = $Filter
    }

    $filterMessage = if ([string]::IsNullOrWhiteSpace($Filter)) { '' } else { " with filter $Filter" }
    Write-Log -Level INFO -Message "Creating Intune export job for report '$ReportName'$filterMessage."

    $job = Invoke-GraphRequestWithRetry `
        -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs' `
        -Body $body

    $jobId = [string](Get-ObjectValue -InputObject $job -Name 'id')
    if ([string]::IsNullOrWhiteSpace($jobId)) {
        throw "The Intune export job for '$ReportName' did not return an ID."
    }

    $jobStartTime = Get-Date
    $deadline = $jobStartTime.AddMinutes($TimeoutMinutes)
    $consecutiveNotFound = 0

    do {
        Start-Sleep -Seconds $PollSeconds

        if ((Get-Date) -ge $deadline) {
            throw "Timed out waiting for Intune report '$ReportName' after $TimeoutMinutes minutes."
        }

        $escapedJobId = [uri]::EscapeDataString($jobId)

        # Keep the status calls on the same Graph version used to create the
        # export job. The parenthesized URI is the primary documented form. The
        # slash form is queried only after a temporary 404, which keeps polling
        # below the per-user exportJobs request limit.
        $primaryStatusUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$escapedJobId')"
        $fallbackStatusUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs/$escapedJobId"

        $job = $null
        $lastStatusError = $null

        try {
            $job = Invoke-GraphRequestWithRetry `
                -Method GET `
                -Uri $primaryStatusUri `
                -MaxAttempts 1
        }
        catch {
            $lastStatusError = $_
            $statusCode = Get-GraphHttpStatusCode -ErrorRecord $_
            $isNotFound = $statusCode -eq 404 -or $_.Exception.Message -match '(?i)(NotFound|Not Found)'

            if (-not $isNotFound) {
                throw
            }

            try {
                $job = Invoke-GraphRequestWithRetry `
                    -Method GET `
                    -Uri $fallbackStatusUri `
                    -MaxAttempts 1
            }
            catch {
                $lastStatusError = $_
                $fallbackStatusCode = Get-GraphHttpStatusCode -ErrorRecord $_
                $fallbackNotFound = $fallbackStatusCode -eq 404 -or $_.Exception.Message -match '(?i)(NotFound|Not Found)'

                if (-not $fallbackNotFound) {
                    throw
                }
            }
        }

        if ($null -eq $job) {
            $consecutiveNotFound++
            $lastErrorText = if ($lastStatusError) { $lastStatusError.Exception.Message } else { 'HTTP 404 Not Found' }
            $notFoundDelay = [Math]::Min(60, [Math]::Max($ReportPollSeconds, 10 * $consecutiveNotFound))
            Write-Log -Level WARN -Message "Export job '$jobId' for '$ReportName' is temporarily unavailable (consecutive 404 count: $consecutiveNotFound). Waiting $notFoundDelay seconds before polling again. Last error: $lastErrorText"
            Start-Sleep -Seconds $notFoundDelay
            continue
        }

        $consecutiveNotFound = 0

        $status = [string](Get-ObjectValue -InputObject $job -Name 'status')
        $elapsedSeconds = [int]((Get-Date) - $jobStartTime).TotalSeconds
        Write-Log -Level INFO -Message "Export status for '$ReportName': $status (elapsed: $elapsedSeconds seconds)"

        if ($status -eq 'failed') {
            throw "The Intune report export job '$jobId' for '$ReportName' failed."
        }
    }
    until ($status -in @('completed', 'complete'))

    $downloadUrl = [string](Get-ObjectValue -InputObject $job -Name 'url')
    if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
        throw "The completed Intune export job for '$ReportName' did not provide a download URL."
    }

    $tempRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("IntuneReport_{0}" -f ([guid]::NewGuid().Guid))
    $downloadPath = Join-Path -Path $tempRoot -ChildPath 'report.zip'
    $extractPath = Join-Path -Path $tempRoot -ChildPath 'extracted'

    New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $extractPath -ItemType Directory -Force | Out-Null

    try {
        Write-Log -Level INFO -Message "Downloading Intune report '$ReportName'."
        $webParams = @{
            Uri         = $downloadUrl
            OutFile     = $downloadPath
            ErrorAction = 'Stop'
        }

        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $webParams.UseBasicParsing = $true
        }

        Invoke-WebRequest @webParams

        $csvFile = $null
        try {
            Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
            $csvFile = Get-ChildItem -Path $extractPath -Filter '*.csv' -File -Recurse | Select-Object -First 1
        }
        catch {
            $csvFile = Get-Item -LiteralPath $downloadPath
        }

        if (-not $csvFile) {
            throw "No CSV file was found in the downloaded '$ReportName' report."
        }

        return @(Import-Csv -LiteralPath $csvFile.FullName)
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-PolicyCandidatesFromConfigurationEndpoints {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName
    )

    $matches = [System.Collections.Generic.List[object]]::new()
    $seenIds = @{}
    $requestedName = Normalize-PolicyName -Value $PolicyName

    $legacyPolicies = Get-GraphCollection -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$select=id,displayName'
    foreach ($policy in $legacyPolicies) {
        $id = [string](Get-ObjectValue -InputObject $policy -Name 'id')
        $name = [string](Get-ObjectValue -InputObject $policy -Name 'displayName')

        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        if ((Normalize-PolicyName -Value $name) -ieq $requestedName) {
            $key = $id.ToLowerInvariant()
            if (-not $seenIds.ContainsKey($key)) {
                $seenIds[$key] = $true
                $matches.Add([pscustomobject]@{
                    Id     = $id
                    Name   = $name
                    Source = 'deviceConfigurations-beta'
                })
            }
        }
    }

    $modernPolicies = Get-GraphCollection -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$select=id,name'
    foreach ($policy in $modernPolicies) {
        $id = [string](Get-ObjectValue -InputObject $policy -Name 'id')
        $name = [string](Get-ObjectValue -InputObject $policy -Name 'name')

        if ([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        if ((Normalize-PolicyName -Value $name) -ieq $requestedName) {
            $key = $id.ToLowerInvariant()
            if (-not $seenIds.ContainsKey($key)) {
                $seenIds[$key] = $true
                $matches.Add([pscustomobject]@{
                    Id     = $id
                    Name   = $name
                    Source = 'configurationPolicies-beta'
                })
            }
        }
    }

    return $matches.ToArray()
}

function Resolve-IntunePolicy {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,

        [Parameter()]
        [string]$PolicyIdOverride,

        [Parameter()]
        [switch]$AllowPoliciesReportFallback,

        [Parameter(Mandatory)]
        [int]$TimeoutMinutes,

        [Parameter(Mandatory)]
        [int]$PollSeconds
    )

    if (-not [string]::IsNullOrWhiteSpace($PolicyIdOverride)) {
        Write-Log -Level INFO -Message "Using manually supplied policy ID $PolicyIdOverride for '$PolicyName'."
        return [pscustomobject]@{
            Id     = $PolicyIdOverride
            Name   = $PolicyName
            Source = 'manual-policy-id'
        }
    }

    $candidateMap = @{}

    foreach ($candidate in @(Get-PolicyCandidatesFromConfigurationEndpoints -PolicyName $PolicyName)) {
        $candidateKey = ([string]$candidate.Id).ToLowerInvariant()
        $candidateMap[$candidateKey] = $candidate
    }

    if ($candidateMap.Count -eq 0 -and $AllowPoliciesReportFallback) {
        Write-Log -Level WARN -Message "Direct policy lookup did not find '$PolicyName'. Trying the optional Policies report fallback."

        $policyInventoryRows = @(Export-IntuneReport `
            -ReportName 'Policies' `
            -Select @('PolicyId', 'PolicyName') `
            -TimeoutMinutes $TimeoutMinutes `
            -PollSeconds $PollSeconds)

        $requestedName = Normalize-PolicyName -Value $PolicyName
        foreach ($row in $policyInventoryRows) {
            $rowId = [string](Get-ObjectValue -InputObject $row -Name 'PolicyId')
            $rowName = [string](Get-ObjectValue -InputObject $row -Name 'PolicyName')

            if ([string]::IsNullOrWhiteSpace($rowId)) {
                continue
            }

            if ((Normalize-PolicyName -Value $rowName) -ieq $requestedName) {
                $rowKey = $rowId.ToLowerInvariant()
                if (-not $candidateMap.ContainsKey($rowKey)) {
                    $candidateMap[$rowKey] = [pscustomobject]@{
                        Id     = $rowId
                        Name   = $rowName
                        Source = 'Policies-report'
                    }
                }
            }
        }
    }

    $candidates = @($candidateMap.Values)

    if ($candidates.Count -eq 0) {
        throw "No Intune configuration policy was found for the exact name '$PolicyName'. Supply its GUID using the corresponding policy ID parameter. Add -UsePoliciesReportFallback only if you want to try the less reliable tenant-wide Policies export."
    }

    if ($candidates.Count -gt 1) {
        $candidateText = ($candidates | ForEach-Object { "$($_.Source):$($_.Id)" }) -join ', '
        throw "Multiple Intune policies were found with the exact name '$PolicyName'. Candidates: $candidateText. Supply the correct policy ID manually."
    }

    $selected = $candidates[0]
    Write-Log -Level SUCCESS -Message "Resolved policy '$PolicyName' to $($selected.Id) using $($selected.Source)."
    return $selected
}

function Get-ConfigurationProfileStatusRows {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyId,

        [Parameter(Mandatory)]
        [int]$TimeoutMinutes,

        [Parameter(Mandatory)]
        [int]$PollSeconds
    )

    $select = @(
        'DeviceName',
        'IntuneDeviceId',
        'PolicyId',
        'PolicyName',
        'PolicyStatus',
        'PspdpuLastModifiedTimeUtc',
        'ReportStatus',
        'UPN'
    )

    $filter = "(PolicyId eq '$PolicyId')"

    try {
        return @(Export-IntuneReport `
            -ReportName 'DeviceStatusesByConfigurationProfile' `
            -Select $select `
            -Filter $filter `
            -TimeoutMinutes $TimeoutMinutes `
            -PollSeconds $PollSeconds)
    }
    catch {
        Write-Log -Level WARN -Message "DeviceStatusesByConfigurationProfile failed for policy $PolicyId. Trying the V3 report. Error: $($_.Exception.Message)"

        return @(Export-IntuneReport `
            -ReportName 'DeviceStatusesByConfigurationProfileV3' `
            -Select $select `
            -Filter $filter `
            -TimeoutMinutes $TimeoutMinutes `
            -PollSeconds $PollSeconds)
    }
}

function Get-LatestStatusByManagedDeviceId {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $index = @{}

    foreach ($row in @($Rows)) {
        $managedDeviceId = [string](Get-ObjectValue -InputObject $row -Name 'IntuneDeviceId')
        if ([string]::IsNullOrWhiteSpace($managedDeviceId)) {
            continue
        }

        $key = $managedDeviceId.ToLowerInvariant()
        if (-not $index.ContainsKey($key)) {
            $index[$key] = $row
            continue
        }

        $existingDate = ConvertTo-DateTimeOffsetOrNull -Value (Get-ObjectValue -InputObject $index[$key] -Name 'PspdpuLastModifiedTimeUtc')
        $candidateDate = ConvertTo-DateTimeOffsetOrNull -Value (Get-ObjectValue -InputObject $row -Name 'PspdpuLastModifiedTimeUtc')

        if ($null -ne $candidateDate -and ($null -eq $existingDate -or $candidateDate -gt $existingDate)) {
            $index[$key] = $row
        }
    }

    return $index
}

function ConvertTo-NormalizedPolicyStatus {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $rawStatus = ([string]$Value).Trim()

    # In DeviceStatusesByConfigurationProfile exports, numeric value 2 maps to
    # the Success state shown in the Intune admin center.
    if ($rawStatus -eq '2') {
        return 'Success'
    }

    switch ($rawStatus.ToLowerInvariant()) {
        'success'    { return 'Success' }
        'succeeded'  { return 'Succeeded' }
        'compliant'  { return 'Compliant' }
        'remediated' { return 'Remediated' }
        default      { return $rawStatus }
    }
}

function Get-EffectivePolicyStatus {
    param([object]$StatusRow)

    if ($null -eq $StatusRow) {
        return $null
    }

    $policyStatus = ConvertTo-NormalizedPolicyStatus -Value (Get-ObjectValue -InputObject $StatusRow -Name 'PolicyStatus')
    if (-not [string]::IsNullOrWhiteSpace($policyStatus)) {
        return $policyStatus
    }

    $reportStatus = ConvertTo-NormalizedPolicyStatus -Value (Get-ObjectValue -InputObject $StatusRow -Name 'ReportStatus')
    if (-not [string]::IsNullOrWhiteSpace($reportStatus)) {
        return $reportStatus
    }

    return $null
}

function New-ResultRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Phase,

        [Parameter(Mandatory)]
        [object]$Device,

        [Parameter()]
        [object]$ManagedDevice,

        [Parameter()]
        [string]$SourceGroupId,

        [Parameter()]
        [string]$TargetGroupId,

        [Parameter()]
        [object]$Certificate,

        [Parameter()]
        [object]$WiredStatusRow,

        [Parameter()]
        [object]$WirelessStatusRow,

        [Parameter()]
        [string]$WiredStatus,

        [Parameter()]
        [string]$WirelessStatus,

        [Parameter()]
        [bool]$WiredSucceeded,

        [Parameter()]
        [bool]$WirelessSucceeded,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter()]
        [string]$ErrorMessage,

        [Parameter()]
        [string]$CertificatePolicyResolvedId,

        [Parameter()]
        [string]$WiredPolicyResolvedId,

        [Parameter()]
        [string]$WirelessPolicyResolvedId
    )

    return [pscustomobject]@{
        Phase                           = $Phase
        DeviceName                      = [string](Get-ObjectValue -InputObject $Device -Name 'displayName')
        EntraObjectId                   = [string](Get-ObjectValue -InputObject $Device -Name 'id')
        EntraDeviceId                   = [string](Get-ObjectValue -InputObject $Device -Name 'deviceId')
        IntuneManagedDeviceId           = if ($ManagedDevice) { [string](Get-ObjectValue -InputObject $ManagedDevice -Name 'id') } else { $null }
        SourceGroupId                   = $SourceGroupId
        TargetGroupId                   = $TargetGroupId
        CertificatePolicyName           = if ($Phase -eq 'Step1-Certificate') { $CertificatePolicyName } else { $null }
        CertificatePolicyId             = if ($Phase -eq 'Step1-Certificate') { $CertificatePolicyResolvedId } else { $null }
        CertificateStatus               = if ($Certificate) { [string](Get-ObjectValue -InputObject $Certificate -Name 'CertificateStatus') } else { $null }
        CertificateThumbprint           = if ($Certificate) { [string](Get-ObjectValue -InputObject $Certificate -Name 'Thumbprint') } else { $null }
        CertificateValidFrom            = if ($Certificate) { [string](Get-ObjectValue -InputObject $Certificate -Name 'ValidFrom') } else { $null }
        CertificateValidTo              = if ($Certificate) { [string](Get-ObjectValue -InputObject $Certificate -Name 'ValidTo') } else { $null }
        WiredPolicyName                 = if ($Phase -eq 'Step2-8021X') { $WiredPolicyName } else { $null }
        WiredPolicyId                   = if ($Phase -eq 'Step2-8021X') { $WiredPolicyResolvedId } else { $null }
        WiredStatus                     = $WiredStatus
        WiredRawPolicyStatus            = if ($WiredStatusRow) { [string](Get-ObjectValue -InputObject $WiredStatusRow -Name 'PolicyStatus') } else { $null }
        WiredRawReportStatus            = if ($WiredStatusRow) { [string](Get-ObjectValue -InputObject $WiredStatusRow -Name 'ReportStatus') } else { $null }
        WiredSucceeded                  = if ($Phase -eq 'Step2-8021X') { $WiredSucceeded } else { $null }
        WiredLastReportedDateTimeUtc    = if ($WiredStatusRow) { [string](Get-ObjectValue -InputObject $WiredStatusRow -Name 'PspdpuLastModifiedTimeUtc') } else { $null }
        WirelessPolicyName              = if ($Phase -eq 'Step2-8021X') { $WirelessPolicyName } else { $null }
        WirelessPolicyId                = if ($Phase -eq 'Step2-8021X') { $WirelessPolicyResolvedId } else { $null }
        WirelessStatus                  = $WirelessStatus
        WirelessRawPolicyStatus         = if ($WirelessStatusRow) { [string](Get-ObjectValue -InputObject $WirelessStatusRow -Name 'PolicyStatus') } else { $null }
        WirelessRawReportStatus         = if ($WirelessStatusRow) { [string](Get-ObjectValue -InputObject $WirelessStatusRow -Name 'ReportStatus') } else { $null }
        WirelessSucceeded               = if ($Phase -eq 'Step2-8021X') { $WirelessSucceeded } else { $null }
        WirelessLastReportedDateTimeUtc = if ($WirelessStatusRow) { [string](Get-ObjectValue -InputObject $WirelessStatusRow -Name 'PspdpuLastModifiedTimeUtc') } else { $null }
        BothProfilesSuccessful          = if ($Phase -eq 'Step2-8021X') { ($WiredSucceeded -and $WirelessSucceeded) } else { $null }
        Action                          = $Action
        Error                           = $ErrorMessage
    }
}

# -----------------------------------------------------------------------------
# Continuous mode controller
# -----------------------------------------------------------------------------

# The default behavior is to run one complete migration/sync cycle, wait 30
# seconds, and start a fresh cycle. The child invocation uses -RunOnce so the
# call depth remains constant instead of recursively growing after every cycle.
if (-not $RunOnce) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Continuous mode requires the script to be saved as a .ps1 file. Use -RunOnce when executing pasted code in an editor selection.'
    }

    $baseChildParameters = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -ne 'RunOnce') {
            $baseChildParameters[$entry.Key] = $entry.Value
        }
    }
    $baseChildParameters['RunOnce'] = $true

    $cycleNumber = 0

    while ($true) {
        $cycleNumber++
        $cycleParameters = @{}
        foreach ($entry in $baseChildParameters.GetEnumerator()) {
            $cycleParameters[$entry.Key] = $entry.Value
        }

        Write-Host ''
        Write-Log -Level INFO -Message "Starting migration cycle $cycleNumber."

        try {
            & $PSCommandPath @cycleParameters
        }
        catch {
            $cycleErrorMessage = $_.Exception.Message
            Write-Log -Level ERROR -Message "Migration cycle $cycleNumber failed: $cycleErrorMessage"
        }

        $nextRun = (Get-Date).AddSeconds($RepeatDelaySeconds)
        Write-Log -Level INFO -Message "Cycle $cycleNumber finished. Sleeping for $RepeatDelaySeconds seconds. Next cycle: $($nextRun.ToString('yyyy-MM-dd HH:mm:ss')). Press Ctrl+C to stop."
        Start-Sleep -Seconds $RepeatDelaySeconds
    }

    return
}

# -----------------------------------------------------------------------------
# Connect once and validate the three groups
# -----------------------------------------------------------------------------

Write-Log -Level INFO -Message 'Connecting to Microsoft Graph using Entra application client secret authentication.'

$secureClientSecret = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
$clientSecretCredential = New-Object System.Management.Automation.PSCredential($ClientId, $secureClientSecret)

Connect-MgGraph `
    -TenantId $TenantId `
    -ClientSecretCredential $clientSecretCredential `
    -NoWelcome

$context = Get-MgContext
Write-Log -Level SUCCESS -Message "Connected using Entra application $($context.ClientId) to tenant $($context.TenantId)."

$step1SourceGroup = Get-GroupDetails -GroupId $Step1SourceGroupId
$step2Group = Get-GroupDetails -GroupId $Step2GroupId
$step3Group = Get-GroupDetails -GroupId $Step3GroupId

Assert-StaticSecurityGroup -Group $step2Group -Purpose 'Step 2 target'
Assert-StaticSecurityGroup -Group $step3Group -Purpose 'Step 3 target'

Write-Log -Level INFO -Message "Step 1 source group: $($step1SourceGroup.displayName) [$Step1SourceGroupId]"
Write-Log -Level INFO -Message "Step 2 group: $($step2Group.displayName) [$Step2GroupId]"
Write-Log -Level INFO -Message "Step 3 group: $($step3Group.displayName) [$Step3GroupId]"

# -----------------------------------------------------------------------------
# Resolve policies and retrieve Intune managed devices once
# -----------------------------------------------------------------------------

$certificatePolicy = Resolve-IntunePolicy `
    -PolicyName $CertificatePolicyName `
    -PolicyIdOverride $CertificatePolicyId `
    -AllowPoliciesReportFallback:$UsePoliciesReportFallback `
    -TimeoutMinutes $ReportTimeoutMinutes `
    -PollSeconds $ReportPollSeconds

$wiredPolicy = Resolve-IntunePolicy `
    -PolicyName $WiredPolicyName `
    -PolicyIdOverride $WiredPolicyId `
    -AllowPoliciesReportFallback:$UsePoliciesReportFallback `
    -TimeoutMinutes $ReportTimeoutMinutes `
    -PollSeconds $ReportPollSeconds

$wirelessPolicy = Resolve-IntunePolicy `
    -PolicyName $WirelessPolicyName `
    -PolicyIdOverride $WirelessPolicyId `
    -AllowPoliciesReportFallback:$UsePoliciesReportFallback `
    -TimeoutMinutes $ReportTimeoutMinutes `
    -PollSeconds $ReportPollSeconds

if ([string]::Equals([string]$wiredPolicy.Id, [string]$wirelessPolicy.Id, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The wired and wireless policy IDs resolved to the same policy. Verify the policy names or provide their IDs manually.'
}

Write-Log -Level INFO -Message 'Retrieving Intune managed devices.'
$managedDevices = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,lastSyncDateTime')

$managedByEntraDeviceId = @{}
foreach ($managedDevice in $managedDevices) {
    $aadDeviceId = [string](Get-ObjectValue -InputObject $managedDevice -Name 'azureADDeviceId')
    if ([string]::IsNullOrWhiteSpace($aadDeviceId)) {
        continue
    }

    $key = $aadDeviceId.ToLowerInvariant()
    if (-not $managedByEntraDeviceId.ContainsKey($key)) {
        $managedByEntraDeviceId[$key] = $managedDevice
        continue
    }

    $existingDate = ConvertTo-DateTimeOffsetOrNull -Value (Get-ObjectValue -InputObject $managedByEntraDeviceId[$key] -Name 'lastSyncDateTime')
    $candidateDate = ConvertTo-DateTimeOffsetOrNull -Value (Get-ObjectValue -InputObject $managedDevice -Name 'lastSyncDateTime')

    if ($null -ne $candidateDate -and ($null -eq $existingDate -or $candidateDate -gt $existingDate)) {
        $managedByEntraDeviceId[$key] = $managedDevice
    }
}

$results = [System.Collections.Generic.List[object]]::new()

# -----------------------------------------------------------------------------
# STEP 1: Cloud PKI SCEP certificate profile -> add to Step 2 group
# -----------------------------------------------------------------------------

Write-Host ''
Write-Log -Level INFO -Message 'Starting Step 1: certificate validation and Step 2 group copy.'

$step1Devices = @(Get-GroupDeviceMembers -GroupId $Step1SourceGroupId -Transitive:$UseTransitiveStep1SourceMembers)
$step2CurrentDevices = @(Get-GroupDeviceMembers -GroupId $Step2GroupId)

Write-Log -Level INFO -Message "Found $($step1Devices.Count) device member(s) in the Step 1 source group."
Write-Log -Level INFO -Message "Found $($step2CurrentDevices.Count) existing device member(s) in the Step 2 group."

$step2ObjectIds = @{}
$step2EvaluationMap = @{}

foreach ($device in $step2CurrentDevices) {
    $objectId = [string](Get-ObjectValue -InputObject $device -Name 'id')
    if (-not [string]::IsNullOrWhiteSpace($objectId)) {
        $key = $objectId.ToLowerInvariant()
        $step2ObjectIds[$key] = $true
        $step2EvaluationMap[$key] = $device
    }
}

$certificateRows = @(Export-IntuneReport `
    -ReportName 'AllDeviceCertificates' `
    -Select @('CertificateStatus', 'DeviceId', 'DeviceName', 'PolicyId', 'SerialNumber', 'SubjectName', 'Thumbprint', 'ValidFrom', 'ValidTo') `
    -TimeoutMinutes $ReportTimeoutMinutes `
    -PollSeconds $ReportPollSeconds)

Write-Log -Level INFO -Message "Imported $($certificateRows.Count) certificate record(s)."

$certificateRowsByManagedDeviceId = @{}
foreach ($row in $certificateRows) {
    if (-not [string]::Equals([string](Get-ObjectValue -InputObject $row -Name 'PolicyId'), [string]$certificatePolicy.Id, [System.StringComparison]::OrdinalIgnoreCase)) {
        continue
    }

    $managedDeviceId = [string](Get-ObjectValue -InputObject $row -Name 'DeviceId')
    if ([string]::IsNullOrWhiteSpace($managedDeviceId)) {
        continue
    }

    $key = $managedDeviceId.ToLowerInvariant()
    if (-not $certificateRowsByManagedDeviceId.ContainsKey($key)) {
        $certificateRowsByManagedDeviceId[$key] = [System.Collections.Generic.List[object]]::new()
    }

    $certificateRowsByManagedDeviceId[$key].Add($row)
}

$acceptedCertificateStatusLookup = @{}
foreach ($acceptedStatus in $AcceptedCertificateStatuses) {
    if (-not [string]::IsNullOrWhiteSpace($acceptedStatus)) {
        $acceptedCertificateStatusLookup[$acceptedStatus.Trim().ToLowerInvariant()] = $true
    }
}

$nowUtc = [datetimeoffset]::UtcNow

foreach ($sourceDevice in $step1Devices) {
    $deviceName = [string](Get-ObjectValue -InputObject $sourceDevice -Name 'displayName')
    $entraObjectId = [string](Get-ObjectValue -InputObject $sourceDevice -Name 'id')
    $entraDeviceId = [string](Get-ObjectValue -InputObject $sourceDevice -Name 'deviceId')
    $managedDevice = $null
    $selectedCertificate = $null
    $action = $null
    $errorMessage = $null

    try {
        if ([string]::IsNullOrWhiteSpace($entraDeviceId)) {
            $action = 'SkippedNoEntraDeviceId'
            Write-Log -Level WARN -Message "$deviceName has no Entra deviceId value. Skipping Step 1."
            continue
        }

        $entraKey = $entraDeviceId.ToLowerInvariant()
        if (-not $managedByEntraDeviceId.ContainsKey($entraKey)) {
            $action = 'SkippedNotIntuneManaged'
            Write-Log -Level WARN -Message "$deviceName was not found as an Intune managed device."
            continue
        }

        $managedDevice = $managedByEntraDeviceId[$entraKey]
        $managedDeviceId = [string](Get-ObjectValue -InputObject $managedDevice -Name 'id')
        if ([string]::IsNullOrWhiteSpace($managedDeviceId)) {
            $action = 'SkippedNoIntuneDeviceId'
            Write-Log -Level WARN -Message "$deviceName has no Intune managed-device ID."
            continue
        }

        $managedKey = $managedDeviceId.ToLowerInvariant()
        $eligibleCertificates = @()

        if ($certificateRowsByManagedDeviceId.ContainsKey($managedKey)) {
            $eligibleCertificates = @(
                $certificateRowsByManagedDeviceId[$managedKey] | Where-Object {
                    $status = [string](Get-ObjectValue -InputObject $_ -Name 'CertificateStatus')
                    $statusAccepted = -not [string]::IsNullOrWhiteSpace($status) -and $acceptedCertificateStatusLookup.ContainsKey($status.Trim().ToLowerInvariant())
                    if (-not $statusAccepted) {
                        return $false
                    }

                    if ($IncludeExpiredCertificates) {
                        return $true
                    }

                    $validTo = ConvertTo-DateTimeOffsetOrNull -Value (Get-ObjectValue -InputObject $_ -Name 'ValidTo')
                    return ($null -ne $validTo -and $validTo.ToUniversalTime() -gt $nowUtc)
                } | Sort-Object -Property @{ Expression = { ConvertTo-DateTimeOffsetOrNull -Value (Get-ObjectValue -InputObject $_ -Name 'ValidTo') }; Descending = $true }
            )
        }

        if ($eligibleCertificates.Count -eq 0) {
            $action = 'SkippedNoEligibleCertificate'
            Write-Log -Level INFO -Message "$deviceName does not have an eligible certificate from '$CertificatePolicyName'."
            continue
        }

        $selectedCertificate = $eligibleCertificates[0]

        if ([string]::IsNullOrWhiteSpace($entraObjectId)) {
            $action = 'SkippedNoEntraObjectId'
            Write-Log -Level WARN -Message "$deviceName has no Entra directory object ID."
            continue
        }

        $targetKey = $entraObjectId.ToLowerInvariant()
        if ($step2ObjectIds.ContainsKey($targetKey)) {
            $action = 'AlreadyMember'
            Write-Log -Level INFO -Message "$deviceName already belongs to '$($step2Group.displayName)'."
            continue
        }

        $operationDescription = "Add device to '$($step2Group.displayName)' because the Cloud PKI SCEP certificate profile was issued"
        if ($PSCmdlet.ShouldProcess($deviceName, $operationDescription)) {
            $body = @{
                '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$entraObjectId"
            }

            Invoke-GraphRequestWithRetry `
                -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/groups/$Step2GroupId/members/`$ref" `
                -Body $body | Out-Null

            $step2ObjectIds[$targetKey] = $true
            $step2EvaluationMap[$targetKey] = $sourceDevice
            $action = 'Added'
            Write-Log -Level SUCCESS -Message "Added $deviceName to '$($step2Group.displayName)'."
        }
        else {
            $action = 'WhatIf'
        }
    }
    catch {
        $action = 'Error'
        $errorMessage = $_.Exception.Message
        Write-Log -Level ERROR -Message "$deviceName failed during Step 1: $errorMessage"
    }
    finally {
        $results.Add((New-ResultRecord `
            -Phase 'Step1-Certificate' `
            -Device $sourceDevice `
            -ManagedDevice $managedDevice `
            -SourceGroupId $Step1SourceGroupId `
            -TargetGroupId $Step2GroupId `
            -Certificate $selectedCertificate `
            -Action $action `
            -ErrorMessage $errorMessage `
            -CertificatePolicyResolvedId ([string]$certificatePolicy.Id)))
    }
}

# Refresh Step 2 membership, then merge any devices added successfully during
# this same run so eventual consistency does not hide them from Step 2 logic.
Write-Log -Level INFO -Message 'Refreshing Step 2 group membership before profile evaluation.'
$step2RefreshedDevices = @(Get-GroupDeviceMembers -GroupId $Step2GroupId -Transitive:$UseTransitiveStep2Members)
foreach ($device in $step2RefreshedDevices) {
    $objectId = [string](Get-ObjectValue -InputObject $device -Name 'id')
    if (-not [string]::IsNullOrWhiteSpace($objectId)) {
        $step2EvaluationMap[$objectId.ToLowerInvariant()] = $device
    }
}

$step2DevicesForEvaluation = @($step2EvaluationMap.Values)

# -----------------------------------------------------------------------------
# STEP 2: both 802.1X profiles successful -> add to Step 3 group
# -----------------------------------------------------------------------------

Write-Host ''
Write-Log -Level INFO -Message 'Starting Step 2: wired and wireless 802.1X profile validation and Step 3 group copy.'
Write-Log -Level INFO -Message "Evaluating $($step2DevicesForEvaluation.Count) device member(s) from the Step 2 group."

$step3CurrentDevices = @(Get-GroupDeviceMembers -GroupId $Step3GroupId)
$step3ObjectIds = @{}
foreach ($device in $step3CurrentDevices) {
    $objectId = [string](Get-ObjectValue -InputObject $device -Name 'id')
    if (-not [string]::IsNullOrWhiteSpace($objectId)) {
        $step3ObjectIds[$objectId.ToLowerInvariant()] = $true
    }
}

$wiredRows = @(Get-ConfigurationProfileStatusRows `
    -PolicyId ([string]$wiredPolicy.Id) `
    -TimeoutMinutes $ReportTimeoutMinutes `
    -PollSeconds $ReportPollSeconds)

$wirelessRows = @(Get-ConfigurationProfileStatusRows `
    -PolicyId ([string]$wirelessPolicy.Id) `
    -TimeoutMinutes $ReportTimeoutMinutes `
    -PollSeconds $ReportPollSeconds)

Write-Log -Level INFO -Message "Imported $($wiredRows.Count) wired policy status row(s)."
Write-Log -Level INFO -Message "Imported $($wirelessRows.Count) wireless policy status row(s)."
Write-Log -Level INFO -Message 'Numeric PolicyStatus value 2 will be interpreted as Success.'

$wiredStatusByManagedDeviceId = Get-LatestStatusByManagedDeviceId -Rows $wiredRows
$wirelessStatusByManagedDeviceId = Get-LatestStatusByManagedDeviceId -Rows $wirelessRows

$acceptedPolicyStatusLookup = @{}
foreach ($acceptedStatus in $AcceptedPolicyStatuses) {
    if (-not [string]::IsNullOrWhiteSpace($acceptedStatus)) {
        $acceptedPolicyStatusLookup[$acceptedStatus.Trim().ToLowerInvariant()] = $true
    }
}

foreach ($sourceDevice in $step2DevicesForEvaluation) {
    $deviceName = [string](Get-ObjectValue -InputObject $sourceDevice -Name 'displayName')
    $entraObjectId = [string](Get-ObjectValue -InputObject $sourceDevice -Name 'id')
    $entraDeviceId = [string](Get-ObjectValue -InputObject $sourceDevice -Name 'deviceId')

    $managedDevice = $null
    $wiredStatusRow = $null
    $wirelessStatusRow = $null
    $wiredStatus = $null
    $wirelessStatus = $null
    $wiredSucceeded = $false
    $wirelessSucceeded = $false
    $action = $null
    $errorMessage = $null

    try {
        if ([string]::IsNullOrWhiteSpace($entraDeviceId)) {
            $action = 'SkippedNoEntraDeviceId'
            Write-Log -Level WARN -Message "$deviceName has no Entra deviceId value. Skipping Step 2."
            continue
        }

        $entraKey = $entraDeviceId.ToLowerInvariant()
        if (-not $managedByEntraDeviceId.ContainsKey($entraKey)) {
            $action = 'SkippedNotIntuneManaged'
            Write-Log -Level WARN -Message "$deviceName was not found as an Intune managed device."
            continue
        }

        $managedDevice = $managedByEntraDeviceId[$entraKey]
        $managedDeviceId = [string](Get-ObjectValue -InputObject $managedDevice -Name 'id')
        if ([string]::IsNullOrWhiteSpace($managedDeviceId)) {
            $action = 'SkippedNoIntuneDeviceId'
            Write-Log -Level WARN -Message "$deviceName has no Intune managed-device ID."
            continue
        }

        $managedKey = $managedDeviceId.ToLowerInvariant()

        if ($wiredStatusByManagedDeviceId.ContainsKey($managedKey)) {
            $wiredStatusRow = $wiredStatusByManagedDeviceId[$managedKey]
            $wiredStatus = Get-EffectivePolicyStatus -StatusRow $wiredStatusRow
        }

        if ($wirelessStatusByManagedDeviceId.ContainsKey($managedKey)) {
            $wirelessStatusRow = $wirelessStatusByManagedDeviceId[$managedKey]
            $wirelessStatus = Get-EffectivePolicyStatus -StatusRow $wirelessStatusRow
        }

        $wiredSucceeded = -not [string]::IsNullOrWhiteSpace($wiredStatus) -and $acceptedPolicyStatusLookup.ContainsKey($wiredStatus.ToLowerInvariant())
        $wirelessSucceeded = -not [string]::IsNullOrWhiteSpace($wirelessStatus) -and $acceptedPolicyStatusLookup.ContainsKey($wirelessStatus.ToLowerInvariant())

        if (-not $wiredSucceeded -or -not $wirelessSucceeded) {
            $action = 'SkippedProfilesNotSuccessful'
            $wiredDisplay = if ([string]::IsNullOrWhiteSpace($wiredStatus)) { 'No status' } else { $wiredStatus }
            $wirelessDisplay = if ([string]::IsNullOrWhiteSpace($wirelessStatus)) { 'No status' } else { $wirelessStatus }
            Write-Log -Level INFO -Message "$deviceName is not ready. Wired: $wiredDisplay | Wireless: $wirelessDisplay"
            continue
        }

        if ([string]::IsNullOrWhiteSpace($entraObjectId)) {
            $action = 'SkippedNoEntraObjectId'
            Write-Log -Level WARN -Message "$deviceName has no Entra directory object ID."
            continue
        }

        $targetKey = $entraObjectId.ToLowerInvariant()
        if ($step3ObjectIds.ContainsKey($targetKey)) {
            $action = 'AlreadyMember'
            Write-Log -Level INFO -Message "$deviceName already belongs to '$($step3Group.displayName)'."
            continue
        }

        $operationDescription = "Add device to '$($step3Group.displayName)' because both 802.1X profiles succeeded"
        if ($PSCmdlet.ShouldProcess($deviceName, $operationDescription)) {
            $body = @{
                '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$entraObjectId"
            }

            Invoke-GraphRequestWithRetry `
                -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/groups/$Step3GroupId/members/`$ref" `
                -Body $body | Out-Null

            $step3ObjectIds[$targetKey] = $true
            $action = 'Added'
            Write-Log -Level SUCCESS -Message "Added $deviceName to '$($step3Group.displayName)'."
        }
        else {
            $action = 'WhatIf'
        }
    }
    catch {
        $action = 'Error'
        $errorMessage = $_.Exception.Message
        Write-Log -Level ERROR -Message "$deviceName failed during Step 2: $errorMessage"
    }
    finally {
        $results.Add((New-ResultRecord `
            -Phase 'Step2-8021X' `
            -Device $sourceDevice `
            -ManagedDevice $managedDevice `
            -SourceGroupId $Step2GroupId `
            -TargetGroupId $Step3GroupId `
            -WiredStatusRow $wiredStatusRow `
            -WirelessStatusRow $wirelessStatusRow `
            -WiredStatus $wiredStatus `
            -WirelessStatus $wirelessStatus `
            -WiredSucceeded $wiredSucceeded `
            -WirelessSucceeded $wirelessSucceeded `
            -Action $action `
            -ErrorMessage $errorMessage `
            -WiredPolicyResolvedId ([string]$wiredPolicy.Id) `
            -WirelessPolicyResolvedId ([string]$wirelessPolicy.Id)))
    }
}

# -----------------------------------------------------------------------------
# DEVICE SYNC: trigger an Intune sync for every unique migration-group device
# -----------------------------------------------------------------------------

Write-Host ''

if ($SkipDeviceSync) {
    Write-Log -Level WARN -Message 'Device sync phase was skipped because -SkipDeviceSync was specified.'
}
else {
    Write-Log -Level INFO -Message 'Starting device sync for all unique devices across the Step 1, Step 2, and Step 3 groups.'

    # The Step 3 query is performed here so devices that existed only in Step 3
    # are also synchronized. Devices added to Step 3 during this execution are
    # already present in $step2DevicesForEvaluation and are therefore included
    # even if Entra group membership has not reached eventual consistency yet.
    $step3DevicesForSync = if ($UseTransitiveStep3Members) {
        @(Get-GroupDeviceMembers -GroupId $Step3GroupId -Transitive)
    }
    else {
        @($step3CurrentDevices)
    }

    $syncDeviceMap = @{}
    $allMigrationDevices = @($step1Devices) + @($step2DevicesForEvaluation) + @($step3DevicesForSync)

    foreach ($device in $allMigrationDevices) {
        $objectId = [string](Get-ObjectValue -InputObject $device -Name 'id')
        $deviceId = [string](Get-ObjectValue -InputObject $device -Name 'deviceId')

        $uniqueKey = if (-not [string]::IsNullOrWhiteSpace($objectId)) {
            "object:$($objectId.ToLowerInvariant())"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            "device:$($deviceId.ToLowerInvariant())"
        }
        else {
            $null
        }

        if ($null -ne $uniqueKey -and -not $syncDeviceMap.ContainsKey($uniqueKey)) {
            $syncDeviceMap[$uniqueKey] = $device
        }
    }

    $syncDevices = @($syncDeviceMap.Values)
    Write-Log -Level INFO -Message "Found $($syncDevices.Count) unique device(s) to synchronize."

    foreach ($device in $syncDevices) {
        $deviceName = [string](Get-ObjectValue -InputObject $device -Name 'displayName')
        $entraDeviceId = [string](Get-ObjectValue -InputObject $device -Name 'deviceId')
        $managedDevice = $null
        $syncAction = $null
        $syncError = $null

        try {
            if ([string]::IsNullOrWhiteSpace($entraDeviceId)) {
                $syncAction = 'SyncSkippedNoEntraDeviceId'
                Write-Log -Level WARN -Message "$deviceName has no Entra deviceId value. Intune sync skipped."
                continue
            }

            $entraKey = $entraDeviceId.ToLowerInvariant()
            if (-not $managedByEntraDeviceId.ContainsKey($entraKey)) {
                $syncAction = 'SyncSkippedNotIntuneManaged'
                Write-Log -Level WARN -Message "$deviceName was not found as an Intune managed device. Sync skipped."
                continue
            }

            $managedDevice = $managedByEntraDeviceId[$entraKey]
            $managedDeviceId = [string](Get-ObjectValue -InputObject $managedDevice -Name 'id')
            if ([string]::IsNullOrWhiteSpace($managedDeviceId)) {
                $syncAction = 'SyncSkippedNoIntuneDeviceId'
                Write-Log -Level WARN -Message "$deviceName has no Intune managed-device ID. Sync skipped."
                continue
            }

            if ($PSCmdlet.ShouldProcess($deviceName, 'Trigger Intune device sync')) {
                $escapedManagedDeviceId = [uri]::EscapeDataString($managedDeviceId)
                $syncUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$escapedManagedDeviceId/syncDevice"

                Invoke-GraphRequestWithRetry `
                    -Method POST `
                    -Uri $syncUri | Out-Null

                $syncAction = 'SyncRequested'
                Write-Log -Level SUCCESS -Message "Intune sync requested for $deviceName."

                if ($SyncDelayMilliseconds -gt 0) {
                    Start-Sleep -Milliseconds $SyncDelayMilliseconds
                }
            }
            else {
                $syncAction = 'SyncWhatIf'
            }
        }
        catch {
            $syncAction = 'SyncError'
            $syncError = $_.Exception.Message
            Write-Log -Level ERROR -Message "Intune sync failed for $deviceName`: $syncError"
        }
        finally {
            $results.Add((New-ResultRecord `
                -Phase 'DeviceSync' `
                -Device $device `
                -ManagedDevice $managedDevice `
                -SourceGroupId "$Step1SourceGroupId;$Step2GroupId;$Step3GroupId" `
                -Action $syncAction `
                -ErrorMessage $syncError))
        }
    }
}

# -----------------------------------------------------------------------------
# Show separate in-memory summaries for both phases
# -----------------------------------------------------------------------------

$step1Results = @($results | Where-Object Phase -eq 'Step1-Certificate')
$step2Results = @($results | Where-Object Phase -eq 'Step2-8021X')
$syncResults = @($results | Where-Object Phase -eq 'DeviceSync')

$step1Added = @($step1Results | Where-Object Action -eq 'Added').Count
$step1Already = @($step1Results | Where-Object Action -eq 'AlreadyMember').Count
$step1WhatIf = @($step1Results | Where-Object Action -eq 'WhatIf').Count
$step1NoCertificate = @($step1Results | Where-Object Action -eq 'SkippedNoEligibleCertificate').Count
$step1Errors = @($step1Results | Where-Object Action -eq 'Error').Count

$step2Added = @($step2Results | Where-Object Action -eq 'Added').Count
$step2Already = @($step2Results | Where-Object Action -eq 'AlreadyMember').Count
$step2WhatIf = @($step2Results | Where-Object Action -eq 'WhatIf').Count
$step2NotReady = @($step2Results | Where-Object Action -eq 'SkippedProfilesNotSuccessful').Count
$step2Errors = @($step2Results | Where-Object Action -eq 'Error').Count

$syncRequested = @($syncResults | Where-Object Action -eq 'SyncRequested').Count
$syncWhatIf = @($syncResults | Where-Object Action -eq 'SyncWhatIf').Count
$syncNotManaged = @($syncResults | Where-Object Action -eq 'SyncSkippedNotIntuneManaged').Count
$syncSkippedOther = @($syncResults | Where-Object Action -in @('SyncSkippedNoEntraDeviceId', 'SyncSkippedNoIntuneDeviceId')).Count
$syncErrors = @($syncResults | Where-Object Action -eq 'SyncError').Count

Write-Host ''
Write-Log -Level SUCCESS -Message "Step 1 completed. Added to Step 2: $step1Added | Already members: $step1Already | WhatIf: $step1WhatIf | No eligible certificate: $step1NoCertificate | Errors: $step1Errors"
Write-Log -Level SUCCESS -Message "Step 2 completed. Added to Step 3: $step2Added | Already members: $step2Already | WhatIf: $step2WhatIf | Profiles not successful: $step2NotReady | Errors: $step2Errors"
if ($SkipDeviceSync) {
    Write-Log -Level WARN -Message 'Device sync completed: skipped by parameter.'
}
else {
    Write-Log -Level SUCCESS -Message "Device sync completed. Requested: $syncRequested | WhatIf: $syncWhatIf | Not Intune managed: $syncNotManaged | Other skipped: $syncSkippedOther | Errors: $syncErrors"
}
