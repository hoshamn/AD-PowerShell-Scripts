Function DisabledUsersLastNDays {
	
	# Set the stage
	CLS
	Write-Host "Disabled users audit by Patrick Deno a.k.a. GhillieHammer."
	Write-Host
	# How many days of history to collect and export
	$Scope = Read-Host "How many days to go back?"
	
	# Pull all of the disabled accounts from Active Directory via Search-ADAccount method in order to only get users
	$Accounts = Search-ADAccount -UsersOnly -AccountDisabled -ResultPageSize 2000 -ResultSetSize $null
	
	# Cycle through them and pull in extra info via Get-ADUser method 
	Foreach ($Account in $Accounts) {

		# User properties
		$UserProps = Get-ADUser $Account -Properties *
		
		# Pull user lasLogin property and translate hash to useful date string
		$Userdate = $UserProps.lastlogon
		$Usertime = [datetime]::FromFileTime($Userdate) # translation to date property
		$UserDate = $Usertime.ToString("yyyy-MM-dd") # translate and format lastLogon date to string
		$ReportDate = (Get-Date).ToString("yyyy-MM-dd") # get and format today's date property to string
		$TimeSpan = New-TimeSpan -Start $UserDate -End $ReportDate # calculate time between both dates 
		$Days = $TimeSpan.Days # ... break it out into number of days
		$Num = $Days.ToString() # ... transform it back to a string again
		$NumDays = $Num + " days since" # ... and make it user friendly
			
		# Only give results from within the time span specified
		If ($UserTime -ge (get-date).AddDays(-$Scope)) {
			
			# Where the magic happens - the data gets colated and put into readable form
			$UserProps | Select @{N='User Name'; E='name'},@{N='Network Alias'; E='SamAccountName'},@{N='Email Address'; E='mail'},@{N='Last Logon'; E={[DateTime]::FromFileTime($_.LastLogon).ToString("yyyy-MM-dd")}},@{N='Time span'; E={$NumDays}},@{N='Branch'; E='office'},@{N='User SID'; E='SID'}
			
		}

	}
	
	# keeping it user friendly
	Write-Host
	Write-Host "Report will be saved to C:\Temp\DisabledUsers.csv."
	Read-Host "Ready to generate and launch report.  Press any key to continue ..."
	Write-Host "Exiting."
	Write-Host

}

# Run the function, sort the data, and export it to a CSV file
DisabledUsersLastNDays | sort 'Last Logon' -descending | Export-CSV "C:\Temp\DisabledUsers.csv" -NoTypeInformation

# Launch CSV file
$Path1 = "C:\Temp\DisabledUsers.csv"
&$path1