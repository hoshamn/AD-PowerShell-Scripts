
Import-Module ActiveDirectory
import-csv C:\NourNet\ExtensionNumber\empInformation.csv |
ForEach {
##mail,EmployeeNumber,givenName,surName,Title,Division,Department
#$name=$_.FirstName+$_.LastName
$mail = $_.Email
# Write-Host $name

Get-ADUser -Filter {EmailAddress -eq $mail} | Set-ADUser -replace @{ extensionAttribute9 = "$($_.extensionAttribute9)" }


}



