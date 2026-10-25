# dev.ps1 - VPN Backend Development Helpers (ASCII safe)

$global:ApiBase = "http://localhost:8080"

function Show-Help {
    Write-Host ""
    Write-Host "VPN Backend Dev Helpers" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host "  . .\dev.ps1                  Load helpers"
    Write-Host ""
    Write-Host "  Health                       GET /healthz"
    Write-Host ""
    Write-Host "  Register-User <email> <pwd>  POST /auth/register"
    Write-Host "  Login-User <email> <pwd>     POST /auth/login"
    Write-Host "  Save-Token <token>           Store access token"
    Write-Host "  Clear-Token                  Clear token"
    Write-Host ""
    Write-Host "  Get-Entitlement [installId]  GET /api/entitlement (guest)"
    Write-Host "  Get-VpnConfig [installId]    GET /api/vpn/config (guest)"
    Write-Host "  Get-MyEntitlement            GET /api/entitlement (user)"
    Write-Host "  Get-MyVpnConfig              GET /api/vpn/config (user)"
    Write-Host ""
    Write-Host "  DB / Tables / Users / Installs / Peers / Entitlements"
    Write-Host ""
}

function Health {
    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/healthz" -Method Get -TimeoutSec 5
        Write-Host "[OK] server is up: $r" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] server not reachable: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "       Run 'go run ./cmd/server' in Terminal 1" -ForegroundColor Yellow
    }
}

function Register-User {
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [Parameter(Mandatory=$true)][string]$Password,
        [string]$InstallId = $null
    )
    $body = @{ email = $Email; password = $Password }
    if ($InstallId) { $body.install_id = $InstallId }

    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/auth/register" -Method Post `
            -ContentType "application/json" `
            -Body ($body | ConvertTo-Json -Compress) `
            -TimeoutSec 10
        Write-Host "[OK] Registered: $Email" -ForegroundColor Green
        $global:AccessToken = $r.access_token
        $global:RefreshToken = $r.refresh_token
        Write-Host "[OK] Access token saved (\$AccessToken)" -ForegroundColor Green
        Write-Host "     Token preview: $($r.access_token.Substring(0, [Math]::Min(30, $r.access_token.Length)))..." -ForegroundColor Gray
        return $r
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $errBody = $_.ErrorDetails.Message
        Write-Host "[FAIL] Register failed (HTTP $statusCode): $errBody" -ForegroundColor Red
        Write-Host "       Email: $Email" -ForegroundColor Yellow
    }
}

function Login-User {
    param(
        [Parameter(Mandatory=$true)][string]$Email,
        [Parameter(Mandatory=$true)][string]$Password
    )
    $body = @{ email = $Email; password = $Password } | ConvertTo-Json -Compress
    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/auth/login" -Method Post `
            -ContentType "application/json" `
            -Body $body `
            -TimeoutSec 10
        Write-Host "[OK] Logged in: $Email" -ForegroundColor Green
        $global:AccessToken = $r.access_token
        $global:RefreshToken = $r.refresh_token
        Write-Host "[OK] Access token saved (\$AccessToken)" -ForegroundColor Green
        return $r
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        Write-Host "[FAIL] Login failed (HTTP $statusCode): $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}

function Save-Token {
    param([Parameter(Mandatory=$true)][string]$Token)
    $global:AccessToken = $Token
    Write-Host "[OK] Token saved" -ForegroundColor Green
}

function Clear-Token {
    $global:AccessToken = $null
    Write-Host "[OK] Token cleared" -ForegroundColor Green
}

function Get-Entitlement {
    param([string]$InstallId = "test-install-123")
    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/api/entitlement" -Method Get `
            -Headers @{ "X-Install-ID" = $InstallId } -TimeoutSec 10
        Write-Host "[OK] Guest entitlement ($InstallId):" -ForegroundColor Green
        $r | ConvertTo-Json -Depth 5
        return $r
    } catch {
        Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-VpnConfig {
    param([string]$InstallId = "test-install-123")
    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/api/vpn/config" -Method Get `
            -Headers @{ "X-Install-ID" = $InstallId } -TimeoutSec 10
        Write-Host "[OK] VPN Config:" -ForegroundColor Green
        Write-Host "     IP:       $($r.allowed_ip)"
        Write-Host "     Endpoint: $($r.endpoint)"
        Write-Host ""
        Write-Host $r.config
        return $r
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        Write-Host "[FAIL] VPN config (HTTP $statusCode): $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}

function Get-MyEntitlement {
    if (-not $global:AccessToken) {
        Write-Host "[FAIL] No token - run Register-User or Login-User first" -ForegroundColor Red
        return
    }
    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/api/entitlement" -Method Get `
            -Headers @{ "Authorization" = "Bearer $global:AccessToken" } -TimeoutSec 10
        Write-Host "[OK] User entitlement:" -ForegroundColor Green
        $r | ConvertTo-Json -Depth 5
        return $r
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        Write-Host "[FAIL] (HTTP $statusCode): $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}

function Get-MyVpnConfig {
    if (-not $global:AccessToken) {
        Write-Host "[FAIL] No token - run Register-User or Login-User first" -ForegroundColor Red
        return
    }
    try {
        $r = Invoke-RestMethod -Uri "$ApiBase/api/vpn/config" -Method Get `
            -Headers @{ "Authorization" = "Bearer $global:AccessToken" } -TimeoutSec 10
        Write-Host "[OK] VPN Config:" -ForegroundColor Green
        Write-Host $r.config
        return $r
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        Write-Host "[FAIL] VPN config (HTTP $statusCode): $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}

function DB {
    psql
}

function Tables {
    psql -c "\dt"
}

function Users {
    psql -c "SELECT id, email, role, email_verified, is_banned, created_at FROM users ORDER BY created_at DESC;"
}

function Installs {
    psql -c "SELECT install_id, platform, last_seen_at FROM anonymous_installs ORDER BY last_seen_at DESC LIMIT 20;"
}

function Peers {
    psql -c "SELECT id, COALESCE(user_id::text, install_id::text) AS owner, allowed_ip, is_active, created_at FROM vpn_peers ORDER BY created_at DESC LIMIT 20;"
}

function Entitlements {
    psql -c "SELECT id, COALESCE(user_id::text, install_id::text) AS owner, granted_by, expires_at, (expires_at > NOW()) AS active FROM entitlements ORDER BY created_at DESC LIMIT 20;"
}

Write-Host ""
Write-Host "[OK] VPN Backend dev helpers loaded. Type Show-Help." -ForegroundColor Green
Write-Host ""