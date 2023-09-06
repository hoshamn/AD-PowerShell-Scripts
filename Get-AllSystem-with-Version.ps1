Get-ADComputer -Filter 'enabled -eq "true"' `
-Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address |
Sort-Object -Property Operatingsystem |
Select-Object -Property Name,DNSHostName,Operatingsystem,OperatingSystemVersion,IPv4Address | Export-CSV "C:\AllComputersVersion.csv" -NoTypeInformation -Encoding UTF8