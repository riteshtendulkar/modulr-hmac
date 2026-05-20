<#
.SYNOPSIS
  Modulr HMAC auth + simple invoker in PowerShell.

.NOTES
  - Requires PowerShell 5+ (works in 7+ too)
  - Default base URL targets Sandbox; adjust for Production.
#>

function New-ModulrHmacHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $ApiKey,                   # aka keyId

        [Parameter(Mandatory=$true)]
        [string] $ApiSecret,               # hmac secret

        [string] $Nonce,                   # optional explicit nonce (UUID recommended)
        [string] $Rfc7231Date,             # optional explicit Date (RFC 7231 / RFC1123)
        [bool]   $IsRetry = $false         # adds x-mod-retry: true when replaying same nonce
    )

    # 1) Date header in RFC 7231 format (GMT). PowerShell/.NET "r" is RFC1123 and matches spec.
    if (-not $Rfc7231Date) {
        $Rfc7231Date = ([DateTime]::UtcNow).ToString("r", [System.Globalization.CultureInfo]::InvariantCulture)
        # Ensures "GMT" and correct zero-padded day/month (per docs common pitfalls)
    }

    # 2) Nonce header (unique per request). Use a GUID by default.
    if (-not $Nonce) { $Nonce = [guid]::NewGuid().ToString() }

    # 3) Signature string (header names must be lowercase; newline is "\n", NOT "\r\n")
    $signatureString = "date: $Rfc7231Date`n" + "x-mod-nonce: $Nonce"

    # 4) HMAC-SHA1 using the *decoded* secret bytes over UTF-8 signature string
    $secretBytes   = [System.Text.Encoding]::ASCII.GetBytes($ApiSecret)
    $dataBytes     = [System.Text.Encoding]::ASCII.GetBytes($signatureString)
    $hmac          = New-Object System.Security.Cryptography.HMACSHA1
  $hmac.key = $secretBytes
  $rawSignature  = $hmac.ComputeHash($dataBytes)

    # 5) Base64 then URL-encode (must be percent-encoded, with uppercase hex e.g. %3D)
    $b64           = [Convert]::ToBase64String($rawSignature)
    $urlEncodedSig = [System.Uri]::EscapeDataString($b64)

    # 6) Build Authorization header
    $authorization = "Signature keyId=""$ApiKey"",algorithm=""hmac-sha1"",headers=""date x-mod-nonce"",signature=""$urlEncodedSig"""

  # Compose headers hashtable
    $headers = @{
        "Authorization" = $authorization
        "Date"          = $Rfc7231Date
        "x-mod-nonce"   = $Nonce
    }
    if ($IsRetry) { $headers["x-mod-retry"] = "true" }  # used when re-sending with the SAME nonce

    return $headers
}

function Invoke-ModulrApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","POST","PUT","PATCH","DELETE")]
        [string] $Method,

        [Parameter(Mandatory=$true)]
        [string] $Path,    # e.g. "customers/{customerId}/accounts"

        [Parameter(Mandatory=$true)]
        [string] $ApiKey,

        [Parameter(Mandatory=$true)]
        [string] $ApiSecret,

        [string] $BaseUrl = "https://api-sandbox.modulrfinance.com/api-sandbox",  # Sandbox base
        [object] $Body = $null,            # will be JSON-serialized when provided
        [hashtable] $ExtraHeaders = $null, # pass accept/content-type etc.
        [bool] $IsRetry = $false
    )

    $headers = New-ModulrHmacHeaders -ApiKey $ApiKey -ApiSecret $ApiSecret -IsRetry:$IsRetry
Write-Output $headers

    # Common: JSON content negotiation
    if (-not $ExtraHeaders) { $ExtraHeaders = @{} }
    if (-not $ExtraHeaders.ContainsKey("accept"))       { $ExtraHeaders["accept"] = "application/json" }
    if ($Body -ne $null -and -not $ExtraHeaders.ContainsKey("content-type")) {
        $ExtraHeaders["content-type"] = "application/json"
    }

    # Merge headers
    foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }

    $uri = "{0}/{1}" -f $BaseUrl.TrimEnd('/'), $Path.TrimStart('/')

    if ($Body -ne $null) {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 100 }
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $json
    } else {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
    }
}

<# =========================
   EXAMPLE USAGE (Sandbox)
   =========================

# Fill these from your Sandbox credentials
$API_KEY    = "<YOUR_API_KEY>"
$API_SECRET = "<YOUR_API_SECRET>"

# Example: list accounts for a customer
$customerId = "<YOUR_CUSTOMER_ID>"
$response = Invoke-ModulrApi `
    -Method GET `
    -Path   ("customers/{0}/accounts" -f $customerId) `
    -ApiKey $API_KEY `
    -ApiSecret $API_SECRET

$response | ConvertTo-Json -Depth 5 | Write-Output

# Example: retrying the SAME request with the SAME nonce (set IsRetry=$true and pass the previous nonce/date if you wish)
# $headers = New-ModulrHmacHeaders -ApiKey $API_KEY -ApiSecretBase64 $API_SECRET -IsRetry:$true -Nonce "<previous-nonce>" -Rfc7231Date "<previous-date>"
#>