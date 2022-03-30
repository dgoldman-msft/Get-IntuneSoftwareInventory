function Get-IntuneSoftwareInventory {
    <#
    .SYNOPSIS
        Collect software inventory from an Intune enrolled device

    .DESCRIPTION
        Collect software inventory from an Intune enrolled device and copy the logs to an Azure Storage Blob

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

    .PARAMETER SearchPath
        Search Path

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

    .NOTES
        Your SAS token must contain the following rights (add, create, write) or your connection will fail with a 403 Authorization error
    #>

    [OutputType([System.String])]
    [CmdletBinding()]
    param (
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

        [string]
        $SasToken,

        [switch]
        $SaveToAzure,

        [string]
        $SearchPath = 'c:\'
    )

    begin {
        [System.Collections.ArrayList] $fileList = @()
        $parameters = $PSBoundParameters

        try {
            if (-NOT(Test-Path -Path $LoggingPath)) {
                $null = New-Item -Path $LoggingPath -ItemType Directory -ErrorAction Stop
                Write-Output "Created new directory: $($LoggingPath)"
            }
        }
        catch {
            Write-Output "ERROR: $_"
        }

        try {
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
            $newLogFile = $env:COMPUTERNAME + $(Get-Random) + $Extension
            Write-Output "Generating software inventory file $($newLogFile) and saving to $($LoggingPath)"
            [PSCustomObject]$fileList | Export-Csv -Path (Join-Path -Path $LoggingPath -ChildPath $newLogFile) -Encoding utf8 -NoTypeInformation -ErrorAction Stop
        }
        catch {
            Write-Output "ERROR: $_"
        }

        try {
            $outpath = "$env:TEMP\azcopy_windows_amd64_10.14.1.zip"
            $url = 'https://azcopyvnext.azureedge.net/release20220315/azcopy_windows_amd64_10.14.1.zip'
            Write-Output "Checking to see if AZCopy has already been downloaded to $($LoggingPath)"

            # Look for AzCopy and if not found download it
            if (-NOT (Test-Path -Path $outpath)) {
                Write-Output "Azcopy not found! Downloading AzCopy to $($env:TEMP)"
                Invoke-WebRequest -Uri $url -OutFile $outpath

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

        if ($parameters.ContainsKey('SaveToAzure')) {
            try {
                Write-Output "Uploading to Azure Storage Blob"
                $cmdArguements = "copy --check-length=false $LoggingPath\$newLogFile $SasToken"
                if (Start-Process -Filepath "$env:TEMP\azcopy_windows_amd64_10.14.1\AzCopy.exe" -NoNewWindow -ArgumentList $cmdArguements -PassThru -Wait -RedirectStandardOutput "$LoggingPath\azcopy.log" -ErrorAction Stop) {
                    Write-Output "Software inventory and Azure.log saved to $($LoggingPath)"
                    if (Get-Content -Path $LoggingPath\azcopy.log | Select-String -Pattern '403') { Write-Output "Transfer Failed" } else { Write-Output "Transfter completed successfully!" }
                }
            }
            catch {
                Write-Output "ERROR: $_"
            }
        }
        else {
            { Write-Output "Not saving to azure. If you want to upload to azure please use the -SaveToAzure parameter." }
        }
    }

    end {
        if ($parameters.ContainsKey('EnableLogging')) { Stop-Transcript }
    }
}

# If you want to use this script locally just comment out the line below
Get-IntuneSoftwareInventory -Recurse -Filter "YourFirst*","YourSecondFilter*" -SaveToAzure -SasToken "YourSASToken"