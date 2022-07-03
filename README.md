# Get-IntuneSoftwareInventory

A helper script that will grab a software inventory based on filter and upload to an Azure Storage Blob. This is useful when looking for certain binaries
for a software package that need to be replaced at a binary level. This will also dump out all of the installed applications as well.

> .EXAMPLE 1 -Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse

        This will search the local drive root of c:\ recursively with a search filter of eaCrash*

> EXAMPLE 2 - Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -EnableLogging

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and save a transcript log file that can be used for troubleshooting analysis

> EXAMPLE 3 - Get-SoftwareInventory -Filter "eaCrash*", "eaDump*" -SearchPath c:\ -Recurse -EnableLogging

        This will search the local drive root of c:\ recursively with a search filter eaCrash* and "eaDump*" then save a transcript log file that can be used for troubleshooting analysis

> EXAMPLE 4 - Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SaveToAzure -SasToken "https://YourSasTokenHere"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and upload the file to an Azure Storage Blob

> EXAMPLE 5 -Get-IntuneSoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SendAsEmail -UseSettingsFileWithSecretKey -SmtpTo "admin@tenant.onmicrosoft.com"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with the compressed attachment using a local settings.json file

> EXAMPLE 6 - Get-IntuneSoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SendAsEmail -TenantID "YourTenantID" -ClientID "YourClientID" -SmtpTo "admin@tenant.onmicrosoft.com"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with all of the supplied tenant and registered application information

> EXAMPLE 7 - Get-IntuneSoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SendAsEmail -UserLocalCert -TenantID "YourTenantID" -ClientID "YourClientID" -SecretKey "YourSecretKey" -SmtpTo "Your account or group receiving the email with attachments"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with the compressed attachment using a local certificate to authenticate to the Azure tenant

> Notes:

* The last few lines of the script is active for Intune interaction. If you wish to use this without Intune comment out any of the last lines

* Your SAS token must contain the following rights (add, create, write) or your connection will fail with a 403 Authorization error

* Using the -UseSettingsFileWithSecretKey switch requires a settings.json file to reside in the local directory with this script file
{
    "TenantId": "Your TenantID",
    "ClientId": "Your ClientID",
    "ClientSecret": "Your Client Secret Key",
    "CertThumbPrint": "Thumbprint of local cert saved to your azure application to read from local certificate store"
}
