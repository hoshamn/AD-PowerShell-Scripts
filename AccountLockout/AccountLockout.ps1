<#
 .SYNOPSIS

  Generates an HTM file for a site listing Active Directory account lockout details. Generates account lockout/unlock alerts for monitored accounts.

 .DESCRIPTION

  Checks the Domain controllers for lockout and unlock events then exports these events to a searchable .HTM file to be used as a website. 
  Sends email alerts for monitored accounts when an event occurs.

 .DEPENDENCIES

  PS Active Directory Module
  OutDataTableView - Taken from http://www.dougfinke.com/blog/index.php/2011/02/15/how-to-send-powershell-output-to-a-jquery-interactive-datatable-in-a-web-browser/ and modified to fit this process.

 .COMPATABILITY

  Tested for: PS v3+

 .NOTES

  NAME:       Account_Lockout_CSV.ps1

  AUTHOR:     Josh Tessaro

  CO-AUTHOR:  Brian Arnold

  CREATED:    09/20/13

  LASTEDIT:   11/18/13
#>

###############
##### PRE #####
###############

###
# The below code is necessary due to this bug: 
# http://social.msdn.microsoft.com/Forums/en-US/edc4ae2d-b804-4361-94de-7482533a8084/intermittent-the-term-getdate-is-not-recognized-as-the-name-of-a-cmdlet-function-script-file?forum=winserverpowershell
###
$Done = 0
$Count = 0

while ($done -eq 0 -and $count -lt 1000)
{
    Try
    {
        import-module Microsoft.Powershell.Management
        import-module Microsoft.Powershell.Security
        import-module Microsoft.Powershell.Utility
        $Done = 1
    }
    Catch
    {
        $Count = $count + 1
    }
}
if ($count -gt 0) 
{
    $error.clear()
    Write-EventLog -EventId $($count + 700) -LogName Application -Message "Count = $count" -Source "Account_Lockout.ps1"
}

###
# The above code is necessary due to this bug: 
# http://social.msdn.microsoft.com/Forums/en-US/edc4ae2d-b804-4361-94de-7482533a8084/intermittent-the-term-getdate-is-not-recognized-as-the-name-of-a-cmdlet-function-script-file?forum=winserverpowershell
###

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Start Transcript.
If( -not (Test-Path "$scriptDir\Transcripts")){New-Item -ItemType Directory -Path "$scriptDir\Transcripts"}
Start-Transcript -Path ("$scriptDir\Transcripts\{0:yyyyMMdd}_Log.txt"  -f $(get-date)) -Append

# Set Start Time
$StartTime = Get-Date

# Set other statics
$FindReplace=@{}
$Monitor = @{}

########################################
##### Enable/Disable Functionality #####
########################################

# Any of the below items can be set to false to disable functionality.

# Send Email alerts for monitored accounts.
$MonitorAccounts = $False # (CHANGE ME)

# Build website for monitoring.
$BuildWebPage = $False # (CHANGE ME)

#####################
##### Variables #####
#####################

Write-Output "** SETTING VARIABLES **"

# Source Descriptions (CHANGE ME)
# This is used during the inital query to append descripttions to the source. For Example if the sourece is a server called 
# HQ-XenApp-Prod05 then you can use this section to change the source to: HQ-XenApp-Prod05 (XenApp Citrix Farm)
# $FindReplace['STRING_TO_MATCH'] = "(DESCRIPTION_TO_ADD)"
# You can have as many or as few keywords as needed, add a new line for each KEYWORD/DESCRIPTION pair
$FindReplace['HQ-XenApp-Prod'] = "(XenApp Citrix Farm)" # (CHANGE ME)
$FindReplace['CISCO'] = "(VPN or Wireless)" # (CHANGE ME)
$FindReplace['HQ-EXCH-Prod'] = "(Exchange)" # (CHANGE ME)

# Variables for Monitored account alerting
If($MonitorAccounts)
{
    # Email Alerts
    $SMTPServer = "Email.DOMAIN.com" # (CHANGE ME)

    # The address from which to send the lockout alerts.
    $SMTPFrom = "Account_Lockout@DOMAIN.com" # (CHANGE ME)

    # Monitored accounts (CHANGE ME)
    # List of monitored groups and the Email address to wich the alert will be sent. Each member of the moitored group is a monitored accout, 
    # if a mebmer of the group gets locked or unlocked an email is sent to the designated email address(es). This list can be as long as desired.
    # $Monitor['AD_GROUP_NAME'] = "EMAIL_ADDRESS_TO_WHICH_TO_SEND_ALERTS"
    # YOu can have as many monitored groups as needed, add a new line fore each GROUP/EMAIL pair. Multiple emails are supported for one alert (Comma Separated).
    $Monitor['Monitored_Service_Account_Lockouts'] = "ADMIN@DOMAIN.com" # (CHANGE ME)
    $Monitor['Monitored_User_Account_Lockouts'] = "TechnicalSupportCenter@DOMAIN.com" # (CHANGE ME)
}

# Variables to build a website
If($BuildWebPage)
{
    # The URL of the webpage (Requires intranet DNS entry)
    $SiteURL="lockout.DOMAIN.com" # (CHANGE ME)

    # The Path to the site directory on the server
    $SiteDir = "E:\inetpub\wwwroot\lockout.DOMAIN.com" # (CHANGE ME)

    # The filename of the logo to be used in the top left of the webpage. This must be located in the $ScriptDir and will be copied to $SiteDir during execution.
    $LogoWebPath = "padlock2.png" # (CHANGE ME) 
    # Current Icon taken from http://icons.mysitemyway.com/ and is free to use.
}

###
# The below variables do not need changed.
###

# Time presets
# Age of events to querry (minutes). 6 minute preset is for a scheduled task running every 5 minutes.
$EventStart = 6 
# Age of event history to keep (Days). Decrease or increase value based on the number of events returned.
$HistTime = 14

# File Locations - These are relative paths and can be left alone.
$DataFile = "$scriptDir\CurrDATA.csv"
$EventLog = "$scriptDir\EventLog.csv"
$htmlfile = "$SiteDir\default.htm"

###################
#### Functions ####
###################

Function ChangeDesc($Desc)
{
    foreach($key in $FindReplace.Keys)
    {
        if($Desc.ToLower().Contains($key.ToLower()))
        {
            $Desc+=" $($FindReplace[$key])"
        }
    }
    Return $Desc
}

###################
##### Modules #####
###################

Write-Output "** IMPORTING MODULES **"

# Import Module to generate HTML page.
Import-Module ActiveDirectory
If($BuildWebPage){ Import-Module "$scriptDir\PSModules\OutDataTableView\OutDataTableView.psm1"}

################
##### MAIN #####
################

# Import the Old events form CSV if it exists, do not import events older than $HistTime days.
if(Test-Path $DataFile)
{
    $OldEvents = @(Import-Csv $DataFile | Where {[DateTime]$_.Time -gt ($StartTime).AddDays(-$HistTime)} | Sort-Object Time,User,Source,EventType)
}

# Querry the domain controller for lockout or unlock events, set and return the five fields for each event (User,Source,Time,EventType,Controller).
$GetEvents = @(foreach($server in (Get-ADDomainController -filter * | select -ExpandProperty Hostname)){ 
    Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=$($StartTime.AddMinutes(-$eventstart));Id=4767,4740} -ComputerName $server -ErrorAction SilentlyContinue | `
        Select-Object @{Name="User";Expression={$_.Properties[0].Value}},`
        @{Name="Source";Expression={
            if($_.ID -eq 4767){"Unlocked By: $($_.Properties[4].Value)"}
            ElseIf($_.ID -eq 4740){$(ChangeDesc($_.Properties[1].Value)) -replace '\\'}
        }},`
        @{Name="Time";Expression={"{0:M/d/yyyy h:mm:ss tt}" -f $_.TimeCreated}},`
        @{Name="EventType";Expression={
            if($_.ID -eq 4767){"Unlock"}
            ElseIf($_.ID -eq 4740){"Lockout"}
        }},`
        @{Name="Controller";Expression={
            if($_.ID -eq 4767){(($server -split '\.')[0]).ToUpper()}
            ElseIf($_.ID -eq 4740){$_.Properties[4].Value -replace '\$'}
        }}
    }) | Sort-Object Time,User,Source,EventType -Unique

# Create the New events list eliminating duplicate events. A check is done against the times for a 3 second margin of error to eliminate duplicate events that would appear 
# different due to the time stamp difference caused by sync latency between the DCs and the PDC
If($GetEvents.count -eq 0)
{
    $NewEvents = @()
}
ElseIf($GetEvents.Count -eq 1)
{
    $NewEvents = @($GetEvents)

    # Write the event to the transcript
    Write-Output "Add: $($GetEvents[0].User) $($GetEvents[0].Source) $($GetEvents[0].Time) $($GetEvents[0].EventType) $($GetEvents[0].Controller)"
}
else
{
    $NewEvents = @($GetEvents[0])

    # Write the event to the transcript
    Write-Output "Add: $($GetEvents[0].User) $($GetEvents[0].Source) $($GetEvents[0].Time) $($GetEvents[0].EventType) $($GetEvents[0].Controller)"
    for($i = 1; $i -lt $GetEvents.Count; $i ++)
    {
        if(($GetEvents[$i-1].User -notlike $GetEvents[$i].User -OR $GetEvents[$i-1].Source -notlike $GetEvents[$i].Source -OR $GetEvents[$i-1].EventType -notlike $GetEvents[$i].EventType -OR `
        [MATH]::Abs(([datetime]$GetEvents[$i-1].Time - [datetime]$GetEvents[$i].Time).TotalSeconds) -gt 3))
        {
            $NewEvents += $GetEvents[$i]
            # Write the event to the transcript
            Write-Output "Add: $($GetEvents[$i].User) $($GetEvents[$i].Source) $($GetEvents[$i].Time) $($GetEvents[$i].EventType) $($GetEvents[$i].Controller)"
        }
        else
        {
            # Write the event to the transcript
            Write-Output "Skip: $($GetEvents[$i].User) $($GetEvents[$i].Source) $($GetEvents[$i].Time) $($GetEvents[$i].EventType) $($GetEvents[$i].Controller)"
        }
    }
}

# Check NewEvents for accounts that require alerts
If($MonitorAccounts)
{
    # Loop through all the entreis in the $monitor hash table, checking for accounts that require alerts.
    foreach($key in $Monitor.Keys)
    {
        foreach($event in $NewEvents)
        {
            # Verify this event has not been seen before so as to avoid repeat alerts.
            if(((Get-ADGroup $key -Properties members).members -contains (get-aduser $($event.user)).distinguishedname) -AND `
            (($OldEvents |?{$event.User -like $_.User -AND $event.Source -like $_.Source -AND $event.Time -like $_.Time -AND $event.EventType -like $_.EventType}).count -eq 0))
            {
                # Notify user/log that a monitored account alert is being sent
                Write-Output "$($event.user) is a monitored account, sending notification...."

                # Send monitored account alert.
                Send-MailMessage -To $($Monitor[$key] -split ',') -From $SMTPFrom -SmtpServer $SMTPServer `
                    -Subject "$($event.User) -- Account $(if($event.EventType -like "Lockout"){"Locked"}elseif($event.EventType -like "Unlock"){"Unlocked"})" `
                    -BodyAsHtml "<FONT SIZE='2' FACE='arial'>User: <b>$($event.user)</b><br>`r`nSource: $($event.source)<br>`r`nTime: $($event.time)<br>`r`n
                                EventType: <b>$($event.EventType)</b><br>`r`n
                                Controller: $($event.Controller)<br><br>`r`n
                                PasswordLastSet: $(Get-ADUser $event.User -Properties pwdlastset | %{"{0:M/d/yyy h:mm:ss t}M" -f [DateTime]::FromFileTime($_.PwdLastSet)})<br>`r`n</font>"
            }
        }
    }
}

# Combine Old and New events list.
$Events = $OldEvents + $NewEvents

# Append NewEvents to running event log file for history/troubleshooting.
$NewEvents | Export-Csv $EventLog -NoTypeInformation -Append

# Remove Duplicate events.
$Events = $Events | Sort-Object Time, User, Source, EventType -Unique

# Call Out-DataTableView to build .htm file for webpage
If($BuildWebPage)
{
    # Copy Icon to web directory if needed.
    If(-not (Test-Path "$SiteDir\$LogoWebPath")){Copy-Item "$scriptDir\$LogoWebPath" "$SiteDir\$LogoWebPath"}

    # Generate web page.
    $Events | Out-DataTableView -Properties User,Source,Time,EventType,Controller `
    -PageHeader "<P><FONT FACE='arial'><img src=$LogoWebPath alt='Logo' style='float:left' /><H2>Account Lockouts - Last $HistTime Days </H2> `
        This list is updated every five minutes and was last generated at <b>$("{0:h:mm t}M" -f $StartTime)</b> on $("{0:M/d/yy}" -f $StartTime).</FONT> </P>" `
    -OutFile $htmlfile -Deploy
}

# Export unique $Events to a .csv file for reference on next run
$Events | Export-Csv $DataFile -NoTypeInformation -Force

################
##### POST #####
################

# Delete Transcripts older than 30 days.
Get-ChildItem "$scriptDir\Transcripts" | Where {$_.LastWriteTime -lt $(get-date).adddays(-30)} | Remove-Item

Exit


# SIG # Begin signature block
# MIIEMAYJKoZIhvcNAQcCoIIEITCCBB0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUg70MeLwo/msAjAw8aFUcC9sM
# kSqgggI6MIICNjCCAaOgAwIBAgIQGyVCx+51BaZN/TtU8y6kkTAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xMzA4MjMxODA5MDFaFw0zOTEyMzEyMzU5NTlaMBcxFTATBgNVBAMTDEpvc2gg
# VGVzc2FybzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1P5MVsMsmjh0hJM7
# WfJ9a+dsCfRlrqyU5/a1jSKqzVjGqWj+BJoJqRbYxaJloCrLHZDS4WrbH9yaMpkU
# JhNTBt87wPROzhRecV8hVBsRy++YJ9+3O+Q3AtCQ6JW30U3pXGGHxiYBORqWUyIG
# +LKKgrOthw9uswLjeZMdPTA/FcUCAwEAAaN2MHQwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwXQYDVR0BBFYwVIAQP9IkDaLZr6h8rp1Ol1kzZKEuMCwxKjAoBgNVBAMTIVBv
# d2VyU2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdIIQKWjfp+EDEbRAyi6ZRpo+
# PDAJBgUrDgMCHQUAA4GBAIP+QPDnatl31dxRVDCRP0rng+K57Ma5rhgxhLBDAc5I
# FdMUoDIkEwtcQdYqbMXkdFBJNAs1Xg4npy5cvQl1AzKJqyODX+EqYmmqDciPPrAE
# jebetNAFOVrcX77XTommxkSYPqCKxrlCxrPlvXOYaO3FLnZ5xXWhwH5gFknmRyzl
# MYIBYDCCAVwCAQEwQDAsMSowKAYDVQQDEyFQb3dlclNoZWxsIExvY2FsIENlcnRp
# ZmljYXRlIFJvb3QCEBslQsfudQWmTf07VPMupJEwCQYFKw4DAhoFAKB4MBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIo2
# DZUWunSs1o7+fHP6YmR9TgHwMA0GCSqGSIb3DQEBAQUABIGAWs/CTtGxcqIzkC/J
# jjRPOqMf+UzSt0LEH4RnfzTV9zmhYmvR07rvuJ7eSkUtTf2tx4RvmqmSFifRayeG
# MMLbZ1Gc35wSOfojJN/ohNcOTls7vkQmu2RAklK6Fi0QpaS7588Tco12hoRQTCi9
# i7T/lcdEaMcrkeMh5asov5o953g=
# SIG # End signature block
