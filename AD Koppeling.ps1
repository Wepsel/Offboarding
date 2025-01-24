# Zorg ervoor dat MSAL.PS module is geïnstalleerd
# Install-Module -Name MSAL.PS -Force

# Voeg hier je Tenant ID, Client ID en Client Secret in
$tenantId = ""
$clientId = "c"
$clientSecret = ""

# Functie om een authenticatietoken te verkrijgen
function Get-AuthToken {
    param (
        [string]$tenantId,
        [string]$clientId,
        [string]$clientSecret
    )
    
    $body = @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }

    try {
        Write-Host "Proberen een authenticatietoken te verkrijgen..."
        $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        Write-Host "Authenticatietoken succesvol verkregen."
        return $tokenResponse.access_token
    } catch {
        Write-Host "Er is een fout opgetreden bij het verkrijgen van het authenticatietoken: $_"
        exit
    }
}

# Functie om alle uitgeschakelde gebruikers op te halen via de beta-endpoint
function Get-AllDisabledUsers {
    param (
        [string]$authToken
    )

    $headers = @{
        "Authorization" = "Bearer $authToken"
        "Content-Type"  = "application/json"
    }

    $uri = "https://graph.microsoft.com/beta/users?$select=displayName,userPrincipalName,accountEnabled"
    $allUsers = @()

    Write-Host "Opvragen van alle gebruikers uit Azure AD via de beta-endpoint..."

    try {
        do {
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
            $allUsers += $response.value

            # Controleer of er een volgende pagina is
            $uri = $response.'@odata.nextLink'
        } while ($uri -ne $null)

        # Filter en toon alle uitgeschakelde gebruikers
        $disabledUsers = $allUsers | Where-Object { $_.accountEnabled -eq $false }
        Write-Host "$($disabledUsers.Count) uitgeschakelde gebruikers gevonden."
        return $disabledUsers
    } catch {
        Write-Host "Er is een fout opgetreden bij het ophalen van gebruikers uit Azure AD: $_"
    }
}

# Functie om apparaten van gebruiker op te halen uit Intune
function Get-UserDevices {
    param (
        [string]$authToken,
        [string]$userEmail
    )
    
    $headers = @{
        "Authorization" = "Bearer $authToken"
        "Content-Type"  = "application/json"
    }

    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=userPrincipalName eq '$userEmail'"
    
    try {
        Write-Host "Apparaten voor gebruiker ophalen: $userEmail"
        $devices = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        return $devices.value
    } catch {
        Write-Host "Er is een fout opgetreden bij het ophalen van de apparaten: $_"
        return @()
    }
}

# Functie om apparaat uit Intune te verwijderen
function Remove-DeviceFromIntune {
    param (
        [string]$authToken,
        [string]$deviceId
    )
    
    $headers = @{
        "Authorization" = "Bearer $authToken"
        "Content-Type"  = "application/json"
    }
    
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId"
    
    try {
        Write-Host "Verwijderen apparaat uit Intune met ID: $deviceId"
        Invoke-RestMethod -Uri $uri -Method Delete -Headers $headers
    } catch {
        Write-Host "Er is een fout opgetreden bij het verwijderen van het apparaat uit Intune: $_"
    }
}

# Functie om apparaat uit Autopilot te verwijderen op basis van het serienummer
function Remove-DeviceFromAutopilot {
    param (
        [string]$authToken,
        [string]$serialNumber
    )
    
    $headers = @{
        "Authorization" = "Bearer $authToken"
        "Content-Type"  = "application/json"
    }
    
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities"
    
    try {
        $autopilotDevices = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $deviceToRemove = $autopilotDevices.value | Where-Object {
            ($_.serialNumber -replace ' ', '') -eq ($serialNumber -replace ' ', '')
        }

        if ($null -ne $deviceToRemove) {
            $autopilotDeviceId = $deviceToRemove.id
            $deleteUri = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$autopilotDeviceId"
            Invoke-RestMethod -Uri $deleteUri -Method Delete -Headers $headers
            Write-Host "Apparaat succesvol verwijderd uit Autopilot."
        }
    } catch {
        Write-Host "Er is een fout opgetreden bij het verwijderen van het apparaat uit Autopilot: $_"
    }
}

# Start continue loop om elke 5 minuten uitgeschakelde gebruikers te controleren
while ($true) {
    Write-Host "Controle uitvoeren voor uitgeschakelde gebruikers en hun apparaten..."

    # Haal het authenticatietoken op
    $authToken = Get-AuthToken -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret

    # Haal alle uitgeschakelde gebruikers op
    $disabledUsers = Get-AllDisabledUsers -authToken $authToken

    # Verwijder apparaten voor elke uitgeschakelde gebruiker
    foreach ($user in $disabledUsers) {
        $userEmail = $user.userPrincipalName
        Write-Host "Verwerken van uitgeschakelde gebruiker: $userEmail"

        # Haal de apparaten van de gebruiker op
        $userDevices = Get-UserDevices -authToken $authToken -userEmail $userEmail

        if ($userDevices.Count -eq 0) {
            Write-Host "Geen apparaten gevonden voor de gebruiker $userEmail."
        } else {
            foreach ($device in $userDevices) {
                $deviceId = $device.id
                $serialNumber = $device.serialNumber

                # Verwijder het apparaat uit Intune
                Remove-DeviceFromIntune -authToken $authToken -deviceId $deviceId

                # Verwijder het apparaat uit Autopilot op basis van het serienummer, indien beschikbaar
                if ($serialNumber -ne "") {
                    Remove-DeviceFromAutopilot -authToken $authToken -serialNumber $serialNumber
                } else {
                    Write-Host "Geen serienummer beschikbaar voor apparaat: $($device.deviceName)"
                }
            }
        }
    }

    Write-Host "Controle voltooid. Wachten gedurende 5 minuten voor de volgende controle."
    Start-Sleep -Seconds 300  # Wacht 5 minuten
}