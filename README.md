# Get-IntuneSoftwareInventory

A helper script that will grab a software inventory based on filter and upload to an Azure Storage Blob. This is useful when looking for certain binaries
for a software package that need to be replaced at a binary level. This will also dump out all of the installed applications as well.

> EXAMPLE 1: Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse

        This will search the local drive root of c:\ recursively with a search filter of eaCrash*

> EXAMPLE 2: Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -EnableLogging

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* then save a transcript log file that can be used for troubleshooting analysis

> EXAMPLE 3: Get-SoftwareInventory -Filter "eaCrash*", "eaDump*" -SearchPath c:\ -Recurse -EnableLogging

        This will search the local drive root of c:\ recursively with a search filter eaCrash* and "eaDump*" then save a transcript log file that can be used for troubleshooting analysis

> EXAMPLE 4: Get-SoftwareInventory -Filter eaCrash* -SearchPath c:\ -Recurse -SaveToAzure -SasToken "https://YourSasTokenHere"

        This will search the local drive root of c:\ recursively with a search filter of eaCrash* and upload the file to an Azure Storage Blob

> Notes:

* The last line of the script is active for Intune pushes. If you wish to use this without Intune comment out the last line

* Your SAS token must contain the following rights (add, create, write) or your connection will fail with a 403 Authorization error
