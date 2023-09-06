Get-ADUser -Filter * -Properties CN | 
    Select-Object @{Label='ParentContainer';Expression={$_.Distinguishedname -replace "CN=$($_.cn),"}} | 
    Group-Object -Property ParentContainer | 
    Select-Object Name,Count