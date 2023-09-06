<#===================================================================================================================
Script Name   	: Get-ServerUptimeReport.ps1
       Purpose	: Displays uptimes for a sorted list of servers from a file or from Active Directory.
       Notes  	: Edit this file with your preferences before launching.
Author        	: Richard Wright
Spiceworks	: Profile : https://community.spiceworks.com/people/richardwright
   Latest script: https://community.spiceworks.com/scripts/show/3557-get-serveruptimereport-ps1
Date Created  	: 9:20 AM 3/21/2016
Last Revision 	: 8:19 AM 4/7/2016
Revision Notes	: Added options to customize, display on screen and/or via email, sort.
Tested on	: Windows Server 2012 R2
Credits	      	: This script was influenced by others like the following:
			Sitaram Pamarthi, http://techibee.com
			Ed Wilson, Microsoft Scripting Guy, 
https://blogs.technet.microsoft.com/heyscriptingguy/2012/08/07/use-powershell-to-create-an-html-uptime-report/
=====================================================================================================================#>
CLS
Write-Host "One moment please... Setting up..."


<#================================
Initialize Settings Instructions
==================================
The servers shown in this report come from either a path\file you designate or are pulled from Active Directory. You have the option to pick 

your preference by editing $ServerNameOption in the Options section below. For example:

$ServerNameOption = "File"
	Set this to "File" if you want to report only on servers listed in a file, otherwise the server names will be pulled from Active 

Directory. When set to "File" the server names will be read from the file you enter for $ServerNameFile in the section following this one. 

This is good if you only want to report on servers in a certain OU, are mission critical, or are ones that you are personally responsible 

for their uptime and reporting. The report will sort the list of servers, by name, automatically.
	NOTE: If $ServerNameOption is not set to "File" Active Directory will be queried for the list of servers.

$ServerNameFile = "C:\Admin\ServerList.txt"
	Set this to the path and filename of a file that lists servers, one per line. 
	NOTE: Be sure this is correct as this script does not check to verify if the path and file exists.

The various $BGColor schemes are for the background colors for the HTML report. You can specify different colors for OnLine, Offline, etc. 

You can choose "Red", "Green", etc. or you can choose the color codes. For example: $BGColorColumn = "#BFC3C4" sets the color of the column 

headers to "#BFC3C4" which is a grey color. 
	NOTE: HTML color codes can be found here: http://html-color-codes.info

$SendEmail = ""
	Set this to "True" if you want to receive an email with the report included. Also edit the To, From, and SmtpServer setting in the 

$smtpsettings group below to reflect your specific email settings and preferences.

$ShowOnScreen = "True"
	Set this to "True" if you want to show the results in the Powershell window as it runs. You will be prompted to press [ENTER] to 

exit the script when it is finished.

$ShowHTMLOnScreen = ""
	Set this to "True" if you want to see the HTML report on the screen after the script has run. This is good if you do not want the 

report sent via email.

$ReportOutFile = "C:\Admin\ServerUptimeReport.html"
	This is the path and filename of the HTML report this script will generate.
	NOTE: Be sure the path exists as this script does not verify. If the file exists it is overwritten.

===================================
Options
Edit these with your preferences:
====================================#>
$ServerNameOption = ""
$ServerNameFile = "C:\Admin\ServerList.txt"
$BGColorColumn = "#BFC3C4"
$BGColorOnline = "#6DC046"
$BGColorOffline = "#D43235"
$BGColorReportTotal = "#4AA7E1"
$SendEmail = ""
$ShowOnScreen = "True"
$ShowHTMLOnScreen = "True"
$ReportOutFile = "C:\Admin\ServerUptimeReport.html"


<#==============================
SMTP Settings
Edit with your email settings:
================================#>
$smtpsettings = @{
	To =  "administrator@hniglabs.com"
	From = "UpTimeReport@hniglabs.com"
	Subject = "Server Uptime Report for $(Get-Date -Format D)"
	SmtpServer = "webmail.hniglabs.com"
	}


<#============================
Do not edit below this line!
==============================#>


<#========
Counters
==========#>
$ServerCount = 0
$SuccessCount = 0
$UnreachableCount = 0


<#====================
HTML Report Settings
======================#>
$Report = "
	<html>
	<head>
		<title> Server Uptime Report </title>
	</head>
	<body {background-color:#D7D8D8;}>
		<H1 Align=`"Center`"> <B>Server Uptime Report </B></H1>
		<H3 Align=`"Center`"> $(Get-Date -Format D) </H3>
		<H3 Align=`"Center`"> $(Get-Date -Format T) </H3>
		<table Border=`"1`" CellPadding=`"3`" Align=`"Center`">
			<tr>
				<td BGColor=$BGColorColumn Align=center><b> SERVER NAME </b></td>
				<td BGColor=$BGColorColumn Align=center><b> STATUS </b></td>
				<td BGColor=$BGColorColumn Align=center><b> UPTIME </b></td>
			</tr>"


<#========================
Query servers for uptime
==========================#>
IF ($ShowOnScreen -eq "True")
{  
	Write-Host
	Write-Host "Server querying initiated."
}


IF ($ServerNameOption -eq "File")
{  
	Write-Host
	Write-Host "Reading server names from file:" $ServerNameFile
	$ServerName = Get-Content -Path $ServerNameFile | Sort
}
Else
{
	Write-Host
	Write-Host "Reading server names from Active Directory."
	Write-Host "One moment please..."
	$ServerName = (Get-ADComputer -Filter { OperatingSystem -like '*Server*'} -Properties *).name | Sort
}


IF ($ShowOnScreen -eq "True")
{  
	CLS
	Write-Host "Server Uptime Report"
	Write-Host $(Get-Date -Format D)
	Write-Host $(Get-Date -Format T)
}


ForEach($Server in $ServerName) {
	$OutputObj = New-Object -TypeName PSobject
	$OutputObj | Add-Member -MemberType NoteProperty -Name ServerName -Value $Server
	$Status = 0
	$ServerCount++
	If(Test-Connection -Computer $Server -count 1 -ea 0) {
		$OutputObj | Add-Member -MemberType NoteProperty -Name Status -Value "Online"
		try {
			$BootTime = (Get-WmiObject win32_operatingSystem -computer $Server -ErrorAction stop).lastbootuptime
			$BootTime = [System.Management.ManagementDateTimeconverter]::ToDateTime($BootTime)
			$Now = Get-Date
			$span = New-TimeSpan $BootTime $Now 
				$Days	 = $span.days
				$Hours   = $span.hours
				$Minutes = $span.minutes 
				$Seconds = $span.seconds
<#===============================
Remove plurals if the value = 1
=================================#>
			If ($Days -eq 1)
				{$Day = "1 day "}
			else
				{$Day = "$Days days "}

			If ($Hours -eq 1)
				{$Hr = "1 hr "}
			else
				{$Hr = "$Hours hrs "}

			If ($Minutes -eq 1)
				{$Min = "1 min "}
			else
				{$Min = "$Minutes mins "}

			If ($Seconds -eq 1)
				{$Sec = "1 sec"}
			else
				{$Sec = "$Seconds secs"}

			$Uptime = $Day + $Hr + $Min + $Sec


<#==================
Create Output List
====================#>
			$OutputObj | Add-Member -MemberType NoteProperty -Name Uptime -Value $Uptime
			$Status=1
			$SuccessCount++
		} catch {
			$OutputObj | Add-Member -MemberType NoteProperty -Name Uptime -Value "Query Failed"
<# Not currently reporting on this... #>
		}

		} else {
			$OutputObj | Add-Member -MemberType NoteProperty -Name Status -Value "Offline"
			$OutputObj | Add-Member -MemberType NoteProperty -Name Uptime -Value "Unreachable"
			$UnreachableCount++
		}


<#===============================================
Display output on screen and add to HTML report
=================================================#>
IF ($ShowOnScreen -eq "True")
{  
	$OutputObj
}

If($Status) {
	$BGColor=$BGColorOnline
	} else {
		$BGColor=$BGColorOffline
	}

$Report += "
	<TR>
		<TD BGColor=$BGColor Align = center>$($OutputObj.ServerName)</TD>
		<TD BGColor=$BGColor Align = center>$($OutputObj.Status)</TD>
		<TD BGColor=$BGColor Align = center>$($OutputObj.Uptime)</TD>
	</TR>"
		}


<#====================
Assemble HTML Report
======================#>
$Report +="
		</table>
		<br>
		<table Border=`"1`" CellPadding=`"3`" Align=`"Center`">
		<tr>
			<td BGColor=$BGColorReportTotal Align = right>Servers Scanned: </td>
			<td BGColor=$BGColorReportTotal Align = right>$ServerCount</td>
		</tr>
		<tr>
			<td BGColor=$BGColorOnline Align = right>Servers Online: </td>
			<td BGColor=$BGColorOnline Align = right>$SuccessCount</td>
		</tr>
		<tr>
			<td BGColor=$BGColorOffline Align = right>Servers Offline: </td>
			<td BGColor=$BGColorOffline Align = right>$UnreachableCount</td>
		</tr>
		</table>
	</body>
	</html>"


$Report | Out-File $ReportOutFile -Force


<#==============================================================================================================
Show HTML report on screen
==============================================================================================================#>
IF ($ShowHTMLOnScreen -eq "True")
{  
	Invoke-Item $ReportOutFile
}


<#==============================================================================================================
Email HTML Report
==============================================================================================================#>
IF ($SendEmail -eq "True")
{  
	Send-MailMessage @smtpsettings -Body $Report -BodyAsHtml
}


IF ($ShowOnScreen -eq "True")
{  
	Write-Host
	Write-Host
	Write-Host "Completed."
	Read-Host -Prompt "Press the [ENTER] key to exit..."
}