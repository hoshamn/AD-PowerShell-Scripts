import-module ActiveDirectory
$datecutoff=(Get-Date).AddDays(-700)
Get-ADComputer -Properties ipv4Address, OperatingSystem, LastLogonDate -Filter{LastLogonDate 
-lt $datecutoff} | Sort LastLogonDate |FT Name, ipv4Address, LastLogonDate -Autosize