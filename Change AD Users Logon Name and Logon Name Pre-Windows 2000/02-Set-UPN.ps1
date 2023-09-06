#This script will change the user UPN on AD by the employeeNumber on the CSV file
#Specify UPN Domain  - should be match the domain name
$Domain = 'nourlabs.net'
 
#Get list of samaccountnames in our targeted OU
$UserList = Get-ADUser -Filter * -SearchBase 'OU=JCD-USERS,DC=nourlabs,DC=net' | `
select -ExpandProperty SamAccountName
 
#Change UPN Suffix from sub domain to primary domain
foreach ($User in $UserList) {
    Get-ADUser $User | Set-ADUser -UserPrincipalName "$User@$Domain"
}
 
#Get-ADUser -Filter * -SearchBase 'OU=ExchangeUsers,DC=nourlabs,DC=com' | select Name, UserPrincipalName
 