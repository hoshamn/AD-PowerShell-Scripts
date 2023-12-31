$DaysInactive = 740
$InactiveDate = (Get-Date).Adddays(-($DaysInactive))
$InactiveDate
$Users = Get-ADUser -Filter { LastLogonDate -lt $InactiveDate -and Enabled -eq $true } -searchbase "OU=Students,OU=ACHB,DC=achb,DC=kfupm,DC=edu,DC=sa" -Properties LastLogonDate | Select-Object @{ Name="Username"; Expression={$_.SamAccountName} }, Name, LastLogonDate, DistinguishedName
ForEach ($Item in $Users){
  Remove-ADUser -Identity $Item.DistinguishedName -Confirm:$false
  Write-Output "$($Item.Username) - Deleted"
}