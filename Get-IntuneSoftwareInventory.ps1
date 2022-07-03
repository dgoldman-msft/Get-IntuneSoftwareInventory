function Get-IntuneSoftwareInventory {
    <#
    .SYNOPSIS
        Collect software inventory from an Intune enrolled device

    .DESCRIPTION
        Collect software inventory from an Intune enrolled device and copy the logs to an Azure Storage Blob

    .PARAMETER ClientID
        ClientID to be used for authentication against a registered applications in the Azure tenant

    .PARAMETER EnableLogging
        Enable full logging

    .PARAMETER Extension
        Extension to save report file

    .PARAMETER Filter
        Search filter

    .PARAMETER LoggingPath
        Local Logging Path or Azure Blob Storage location

    .PARAMETER Recurse
        Search directories recursively

    .PARAMETER SaveToAzure
        Indicate save file is to be uploaded to an Azure Storage Blob

    .PARAMETER SasToken
        Temporary write access token for Azure Storage Blob

    .PARAMETER SendAsEmail
        Email the results in an attachment

    .PARAMETER SearchPath
        Search Path

    .PARAMETER SecretKey
		SecretKey to be used for authentication against a registered applications in the Azure tenant

    .PARAMETER SmtpTo
        Smtp address of distribution group or using receiving uploaded reports

    .PARAMETER TenantID
        TenantID of the Azure tenant we are authenticating against

    .PARAMETER UseLocalCert
        Switch to indicated we are looking for an authenticating certificate from the local certificate store

    .PARAMETER UseSettingsFileWithSecretKey
        Use locally store json settings file

    .EXAMPLE
        C:\PS> Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse

        This will search the local drive root of c:\ recursively with a search filter of eaCrash*

    .EXAMPLE
        C:\PS> Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -EnableLogging

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and save a transcript log file that can be used for troubleshooting analysis

    .EXAMPLE
        C:\PS> Get-SoftwareInventory -Filter "eaCrash*", "eaDump*" -SearchPath c:\ -Recurse -EnableLogging

        This will search the local drive root of c:\ recursively with a search filter eaCrash* and "eaDump*" then save a transcript log file that can be used for troubleshooting analysis
    .EXAMPLE
        C:\PS> Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SaveToAzure -SasToken "https://YourSasTokenHere"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and upload the file to an Azure Storage Blob

    .EXAMPLE
        C:\PS> Get-IntuneSoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SendAsEmail -UseSettingsFileWithSecretKey -SmtpTo "admin@tenant.onmicrosoft.com"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with the compressed attachment using a local settings.json file

    .EXAMPLE
        C:\PS> Get-IntuneSoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SendAsEmail -TenantID "YourTenantID" -ClientID "YourClientID" -SmtpTo "admin@tenant.onmicrosoft.com"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with all of the supplied tenant and registered application information

    .EXAMPLE
        C:\PS> Get-IntuneSoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SendAsEmail -UserLocalCert -TenantID "YourTenantID" -ClientID "YourClientID" -SecretKey "YourSecretKey" -SmtpTo "Your account or group receiving the email with attachments"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with the compressed attachment using a local certificate to authenticate to the Azure tenant

    .NOTES
        1. Your SAS token must contain the following rights (add, create, write) or your connection will fail with a 403 Authorization error
        2. SecretKey can be passed in or read in using a settings.json file. This requires an Azure registered application
    #>

    [OutputType([System.String])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [string]
        $ClientID,

        [switch]
        $EnableLogging,

        [string]
        $Extension = '.csv',

        [string[]]
        $Filter = '*',

        [string]
        $LoggingPath = 'c:\SoftwareInventory',

        [switch]
        $Recurse,

        [Parameter(ParameterSetName = 'Azure')]
        [string]
        $SasToken,

        [Parameter(ParameterSetName = 'Azure')]
        [switch]
        $SaveToAzure,

        [Parameter(ParameterSetName = 'Email')]
        [switch]
        $SendAsEmail,

        [string]
        $SearchPath = 'c:\',

        [Parameter(ParameterSetName = 'Email')]
        [string]
        $SecretKey,

        [Parameter(ParameterSetName = 'Email')]
        [string]
        $SmtpTo,

        [Parameter(ParameterSetName = 'Email')]
        [string]
        $TenantID,

        [Parameter(ParameterSetName = 'Email')]
        [switch]
        $UseLocalCert,

        [Parameter(ParameterSetName = 'Email')]
        [switch]
        $UseSecretKey,

        [Parameter(ParameterSetName = 'Email')]
        [Parameter(ParameterSetName = 'SettingsFile')]
        [switch]
        $UseSettingsFileWithSecretKey
    )

    begin {
        [System.Collections.ArrayList] $fileList = @()
        [System.Collections.ArrayList] $applicationList = @()
        $parameters = $PSBoundParameters
        $workingDirectory = $PSSCriptRoot
        Write-Output "Working directory: $($workingDirectory)"

        try {
            if (-NOT(Test-Path -Path $LoggingPath)) {
                $null = New-Item -Path $LoggingPath -ItemType Directory -ErrorAction Stop
                Write-Output "Created new directory: $($LoggingPath)"
            }
            else {
                # Remove older logs so we do not copy up duplicates to the Azure Storage Blob
                Remove-Item -Path $LoggingPath\*.* -Force -ErrorAction Stop
                Write-Output "Removed older logs from: $($LoggingPath)"
            }
        }
        catch {
            Write-Output "ERROR: $_"
        }

        try {
            # If logging is enabled this will also be copied up to the Azure Storage Blob for analysis
            if ($parameters.ContainsKey('EnableLogging')) { Start-Transcript -Path (Join-Path -Path $LoggingPath -ChildPath 'Transcript.log') -Append -ErrorAction Stop }
        }
        catch {
            Write-Output "ERROR: $_"
        }
    }

    process {
        foreach ($query in $Filter) {
            if ($parameters.ContainsKey('Recurse')) {
                Write-Output "Searching $SearchPath recursively and filter used: $query"
                $files = Get-ChildItem -Path $SearchPath -Filter $query -Recurse -ErrorAction SilentlyContinue
            }
            else {
                Write-Output "Searching $SearchPath and filter used: $query"
                $files = Get-ChildItem -Path $SearchPath -Filter $query -ErrorAction SilentlyContinue
            }

            foreach ($file in $files) {
                $found = [PSCustomObject]@{
                    MachineName    = $env:COMPUTERNAME
                    Name           = $file.Name
                    Attributes     = $file.Attributes
                    PSDrive        = $file.PSDrive
                    CreationTime   = $file.CreationTime
                    Directory      = $file.Directory
                    FileVersion    = $file.VersionInfo.FileVersion
                    FileLanguage   = $file.VersionInfo.Language
                    IsDebug        = $file.VersionInfo.IsDebug
                    IsPatched      = $file.VersionInfo.IsPatched
                    IsPreRelease   = $file.VersionInfo.IsPreRelease
                    IsPrivateBuild = $file.VersionInfo.IsPrivateBuild
                    IsSpecialBuild = $file.VersionInfo.IsSpecialBuild
                }
                $null = $fileList.add($found)
            }
        }

        try {
            # Save data to disk
            $newLogFile = $env:COMPUTERNAME + "-SpecificApps-" + $(Get-Random) + $Extension
            Write-Output "Saving specific application search file $($newLogFile) and saving to $($LoggingPath)"
            [PSCustomObject]$fileList | Sort-Object | Export-Csv -Path (Join-Path -Path $LoggingPath -ChildPath $newLogFile) -Encoding utf8 -NoTypeInformation -ErrorAction Stop
        }
        catch {
            Write-Output "ERROR: $_"
        }

        try {
            Write-Output "Collecting full software application list from local machine"
            $applications = Get-CimInstance -Class Win32_Product

            foreach ($application in $applications) {
                if (-NOT ($application.Name)) { continue }
                $found = [PSCustomObject]@{
                    MachineName  = $env:COMPUTERNAME
                    Name         = $application.Name
                    Vendor       = $application.Vendor
                    Version      = $application.Version
                    InstallDate  = $([Datetime]::ParseExact($application.InstallDate, 'yyyyMMdd', $null) -replace "00:00:00", "")
                    PackageCache = $application.PackageCache
                    PackageCode  = $application.PackageCode
                }
                $null = $applicationList.add($found)
            }

            $softwareLogFile = $env:COMPUTERNAME + "-SofwareList-" + $(Get-Random) + $Extension
            Write-Output "Saving full application list file to $($softwareLogFile) and saving to $($LoggingPath)"
            [PSCustomObject]$applicationList | Sort-Object Vendor | Export-Csv -Path (Join-Path -Path $LoggingPath -ChildPath $softwareLogFile) -Encoding utf8 -NoTypeInformation -ErrorAction Stop

            # Compress files to zip archive
            Write-Output "Compressing log files"
            Compress-Archive -Path "C:\SoftwareInventory\*.*" -DestinationPath "C:\SoftwareInventory\$env:COMPUTERNAME.zip" -ErrorAction Stop
        }
        catch {
            Write-Output "ERROR: $_"
        }

        if ($parameters.ContainsKey('SaveToAzure')) {
            try {
                $outpath = "$env:TEMP\azcopy_windows_amd64_10.14.1.zip"
                $url = 'https://azcopyvnext.azureedge.net/release20220315/azcopy_windows_amd64_10.14.1.zip'
                Write-Output "Checking to see if AZCopy has already been downloaded to $($LoggingPath)"

                # Look for AzCopy and if not found download it
                if (-NOT (Test-Path -Path $outpath)) {
                    Write-Output "Azcopy not found! Downloading AzCopy to $($env:TEMP)"
                    Invoke-WebRequest -Uri $url -OutFile $outpath -ErrorAction Stop

                    # Unarchive the zip file to the temp directory
                    if (Expand-Archive -Path "$env:TEMP\azcopy_windows_amd64_10.14.1.zip" -DestinationPath $env:Temp -PassThru -Force -ErrorAction Stop) {
                        Write-Output "AzCopy has been extracted to: $($env:TEMP)"
                    }
                }
                else {
                    Write-Output "AzCopy has been previously downloaded!"
                }
            }
            catch {
                Write-Output "ERROR: $_"
            }

            if ($parameters.ContainsKey('EnableLogging')) {
                Stop-Transcript
                if (Rename-Item -Path "$LoggingPath\Transcript.log" -NewName $($env:COMPUTERNAME + "-Transcript.log") -Force -PassThru -ErrorAction Stop) {
                    $cmdArguements = "copy --check-length=false $LoggingPath\$env:COMPUTERNAME* $SasToken"
                    if (Start-Process -Filepath "$env:TEMP\azcopy_windows_amd64_10.14.1\AzCopy.exe" -NoNewWindow -ArgumentList $cmdArguements -PassThru -Wait -RedirectStandardOutput "$LoggingPath\azcopy.log" -ErrorAction Stop) {
                        Write-Output "Completed!"
                    }
                }
                else {
                    Write-Output "Rename failed! Not uploading Transcript.log"
                }
            }
            try {
                Write-Output "Uploading files to Azure Storage Blob"
                $cmdArguements = "copy --check-length=false $LoggingPath\$env:COMPUTERNAME* $SasToken"
                if (Start-Process -Filepath "$env:TEMP\azcopy_windows_amd64_10.14.1\AzCopy.exe" -NoNewWindow -ArgumentList $cmdArguements -PassThru -Wait -RedirectStandardOutput "$LoggingPath\azcopy.log" -ErrorAction Stop) {
                    Write-Output "Software inventory and Azure.log saved to $($LoggingPath)"
                    if (Get-Content -Path $LoggingPath\azcopy.log | Select-String -Pattern '403') { Write-Output "Transfer Failed" } else { Write-Output "Transfter completed successfully!" }
                }
            }
            catch {
                Write-Output "ERROR: $_"
            }
        }

        if ($parameters.ContainsKey('SendAsEmail')) {
            try {
                if ($parameters.ContainsKey('EnableLogging')) {
                    Stop-Transcript
                    Write-Output "Logging stopped"
                }
                if ($parameters.ContainsKey('UseSettingsFileWithSecretKey')) {
                    Write-Output "Checking for settings.json file"
                    if (Test-Path -Path "$workingDirectory\settings.json") {
                        $jsonObject = Get-Content -Path settings.json | ConvertFrom-Json -ErrorAction Stop
                        $appRegistration = @{
                            TenantId     = $jsonObject.TenantId
                            ClientId     = $jsonObject.ClientId
                            ClientSecret = (ConvertTo-SecureString $jsonObject.ClientSecret -AsPlainText -Force -ErrorAction Stop)
                        }
                    }
                    else {
                        throw "No settings.json file found."
                    }
                }
                elseif ($parameters.ContainsKey('TenantID') -and $parameters.ContainsKey('ClientID') -and $parameters.ContainsKey('SecretKey')) {
                    Write-Output "Authenticating with locally supplied information"
                    $appRegistration = @{
                        TenantId     = $TenantID
                        ClientId     = $ClientID
                        ClientSecret = (ConvertTo-SecureString $SecretKey -AsPlainText -Force -ErrorAction Stop)
                    }
                }
                elseif ($parameters.ContainsKey('UseLocalCert')) {
                    Write-Output "Authenticating with Local Certificate"
                    $appRegistration = @{
                        TenantId          = $TenantID
                        ClientID          = $ClientID
                        ClientCertificate = (Get-Item "Cert:\CurrentUser\My\$($jsonObject.CertThumbPrint)")
                    }
                }

                Write-Output "Obtaining token from Azure"
                $msalToken = Get-MsalToken @appRegistration -ForceRefresh -ErrorAction Stop
                $attachementPath = "C:\SoftwareInventory\$env:COMPUTERNAME.zip"
                $byteStream = Get-Content -Path $attachementPath -AsByteStream -ErrorAction Stop
                $attachementBytes = [System.Convert]::ToBase64String($byteStream)

                # request body which contains our message
                Write-Output "Generating message"
                $requestBody = @{
                    "message"         = [PSCustomObject]@{
                        "subject"      = "Intune Software Inventory Collection"
                        "body"         = [PSCustomObject]@{
                            "contentType" = "Text"
                            "content"     = "Attachements Included"
                        }
                        "toRecipients" = @(
                            [PSCustomObject]@{
                                "emailAddress" = [PSCustomObject]@{
                                    "address" = $SmtpTo
                                }
                            }
                        )
                        "attachments"  = @(
                            @{
                                "@odata.type"  = "#microsoft.graph.fileAttachment"
                                "name"         = $attachementPath
                                "contentType"  = "text/plain"
                                "contentBytes" = $attachementBytes
                            })
                    }
                    "saveToSentItems" = "true"
                }

                # make the graph request
                Write-Output "Generating GraphAPI request"
                $request = @{
                    "Headers"     = @{Authorization = $msalToken.CreateAuthorizationHeader() }
                    "Method"      = "Post"
                    "Uri"         = "https://graph.microsoft.com/v1.0/users/$SmtpTo/sendMail"
                    "Body"        = $requestBody | ConvertTo-Json -Depth 5
                    "ContentType" = "application/json"
                }

                Write-Output "Sending email with attachment to $($SmtpTo)"
                Invoke-RestMethod @request -ErrorAction Stop
                Write-Output "Finished"
            }
            catch {
                Write-Output "ERROR: $_"
            }
        }

        if ($parameters.ContainsKey('EnableLogging')) {
            Stop-Transcript
            Write-Output "Logging stopped"
        }
    }
}

# If you want to use for Azure uncomment the first line or one of the last 3 based on your configuration. Update each line as needed
#Get-IntuneSoftwareInventory -Recurse -Filter "YourFirst*", "YourSecondFilter*" -SaveToAzure -SasToken "YourSASToken"
#Get-IntuneSoftwareInventory -SearchPath c:\ -Recurse -SendAsEmail -UseSettingsFileWithSecretKey -SmtpTo "admin@tenant.onmicrosoft.com"
#Get-IntuneSoftwareInventory -SearchPath c:\ -Recurse -SendAsEmail -TenantID "YourTenantID" -ClientID "YourClientID" -SmtpTo "admin@tenant.onmicrosoft.com"
#Get-IntuneSoftwareInventory -SearchPath c:\ -Recurse -SendAsEmail -UserLocalCert -TenantID "YourTenantID" -ClientID "YourClientID" -SecretKey "YourSecretKey" -SmtpTo "admin@tenant.onmicrosoft.com"