# Get-IntuneSoftwareInventory

A helper script that will grab a software inventory based on filter and upload to an Azure Storage Blob or send results back to an email address of your choice. This is useful when looking for certain binaries for a software package that need to be replaced at a binary level. This will also dump out all installed applications.

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

> EXAMPLE 8 - Get-IntuneSoftwareInventory -SearchPath c:\ -Recurse -Filter eaCrash* -SendAsEmail -UseSettingsFromPSFramework -TenantID "YourTenantID" -ClientID "YourClientID" -SecretKey "YourSecretKey" -SmtpTo "admin@tenant.onmicrosoft.com"

This will search the local drive root of c:\ recursively with a search filter of eaCrash* and send an email to a specified group or account with the compressed attachment using the PSFramework configuration to the Azure tenant. * see note #2

## Notes

* If you want to use the -SendAsEmail feature you will need to create an registered Azure Application in your tenant.
  
You can upload a certificate to the application. Allows for unattendedauthentication
  - You can create a SecretKey. Allows for unattended authentication
  - ReplyURL for PowerShell 5.1 must be: https://login.microsoftonline.com/common/oauth2/nativeclient
  - ReplyURL for PowerShell 6 and above ReplyURL must be: https://localhost

* (More information on Client Flow for unattended used
  - [Interactive - Scripts which run interactively on-demand with user sign-in Delegated authorization code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
  - [Client secret - Unattended automation with secret stored in a key vault Application client credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
  - [Certificate - Unattended automation like scheduled tasks, azure automation Application client credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
  
* How to use via Intune
  - The last few lines of the script is active for Intune interaction. If you wish to use this without Intune comment out any of the last lines

* How to use via PSFramework

  - If you are using EXAMPLE 8 you only need to pass in the TenantID, ClientID and SecretKey just the very first time if you are using PSFramework. It will save the settings to the configuration system and check for them on the next run. SecretKey will be stored securely. You can also pass them in if you want your values to be saved to the PSFramework system configuration.

* How to use via Azure subscription
  - Your SAS token must contain the following rights (add, create, write) or your connection will fail with a 403 Authorization error

* How to use via settings.json file
  - Using the -UseSettingsFileWithSecretKey switch requires a settings.json file to reside in the local directory with this script file
{
    "TenantId": "Your TenantID",
    "ClientId": "Your ClientID",
    "ClientSecret": "Your Client Secret Key",
    "CertThumbPrint": "Thumbprint of local cert saved to your azure application to read from local certificate store"
}
