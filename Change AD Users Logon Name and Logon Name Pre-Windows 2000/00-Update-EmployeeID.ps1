#Put CSV file contain SAMAccountName and employeeNumber
$users=Import-Csv C:\scripts\Change-AD-Users-LogonName\Real-JCD-Users.csv

#This code will set the value employeeNumer in the CSV to SamAccountName in AD
foreach($user in $users){
Get-Aduser $user.SamAccountName |set-aduser -employeeid $user.employeeNumber
}