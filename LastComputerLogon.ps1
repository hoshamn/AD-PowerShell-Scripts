import-module ActiveDirectory
Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem, LastLogonDate | Sort LastLogonDate |
select Name, ipv4Address, OperatingSystem, LastLogonDate |
out-file C:\Computers-lastlogon.txt -Append