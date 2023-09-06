#This script will change the user samaccountname on AD by the employeeNumber on the CSV file

$users=Import-Csv C:\scripts\Change-AD-Users-LogonName\Real-JCD-Users.csv

foreach($user in $users){
Get-Aduser $user.samaccountname|set-aduser -samaccountname $user.employeeNumber

}