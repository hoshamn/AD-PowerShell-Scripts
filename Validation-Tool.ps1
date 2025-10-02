#Requires -Version 5.0
<#
.SYNOPSIS
    Infrastructure Validation Tool with Credential and Permission Validation
.DESCRIPTION
    Professional validation with Excel-style tables and permission checking
.NOTES
    Version: 2.5
    Author: Hisham Nasur - NourNet - MS-TEAM1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# NOTE: This is PART 1 of the script. Due to size limits, you need to combine this with the remaining functions.
# I'll provide you with simple copy-paste instructions after this.

# Global Variables
$Script:Results = @{}
$Script:ConnectionStatus = @{}
$Script:Credential = $null
$Script:ServerInventory = @()
$Script:CurrentResults = @{}
$Script:ExchangeSessions = @{}
$Global:MainForm = $null
$Global:TabControl = $null
$Global:StatusLabel = $null
$Global:CredentialLabel = $null
$Global:ConnectButton = $null
$Global:ProgressBar = $null
$Global:ProgressLabel = $null
$Global:ProgressTotalSteps = 0
$Global:ProgressCurrentStep = 0
$Global:ValidationInProgress = $false

$Script:Colors = @{
    Success = [System.Drawing.Color]::FromArgb(212, 237, 218)
    Error = [System.Drawing.Color]::FromArgb(248, 215, 218)
    Warning = [System.Drawing.Color]::FromArgb(255, 243, 205)
    Info = [System.Drawing.Color]::FromArgb(217, 237, 247)
    Header = [System.Drawing.Color]::FromArgb(44, 62, 80)
    GridHeader = [System.Drawing.Color]::FromArgb(52, 73, 94)
}

#region Helper Functions

function Connect-WithCredentials {
    $NewCredential = Get-Credential -Message "Enter domain credentials for server access"
    
    if ($NewCredential) {
        Update-Status "Validating credentials..."
        
        # Validate credentials first
        $ValidationResult = Test-CredentialValidity -Credential $NewCredential
        
        if ($ValidationResult.Valid) {
            $Script:Credential = $NewCredential
            $Script:ConnectionStatus.Clear()
            Update-CredentialDisplay
            
            [System.Windows.Forms.MessageBox]::Show(
                "Connected successfully as: $($Script:Credential.UserName)`n`nCredentials have been validated.",
                "Authentication Successful",
                "OK",
                "Information"
            )
            Update-Status "Connected as: $($Script:Credential.UserName)"
            return $true
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Authentication Failed!`n`n$($ValidationResult.Message)`n`nPlease check your username and password.",
                "Authentication Failed",
                "OK",
                "Error"
            )
            Update-Status "Authentication failed"
            return $false
        }
    }
    return $false
}

function Disconnect-Credentials {
    if ($Script:Credential) {
        $Result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to disconnect?`n`nCurrent User: $($Script:Credential.UserName)",
            "Confirm Disconnect",
            "YesNo",
            "Question"
        )
        
        if ($Result -eq "Yes") {
            $Script:Credential = $null
            $Script:ConnectionStatus.Clear()
            
            foreach ($ServerName in $Script:ExchangeSessions.Keys) {
                Disconnect-ExchangeRemote -ServerName $ServerName
            }
            
            Update-CredentialDisplay
            Update-Status "Disconnected - No credentials loaded"
            
            [System.Windows.Forms.MessageBox]::Show(
                "Disconnected successfully",
                "Disconnected",
                "OK",
                "Information"
            )
            return $true
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show(
            "No active connection to disconnect",
            "Not Connected",
            "OK",
            "Information"
        )
    }
    return $false
}

function Update-CredentialDisplay {
    if ($Global:CredentialLabel) {
        if ($Script:Credential) {
            $Global:CredentialLabel.Text = "Connected: $($Script:Credential.UserName)"
            $Global:CredentialLabel.ForeColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
            
            if ($Global:ConnectButton) {
                $Global:ConnectButton.Text = "Disconnect"
                $Global:ConnectButton.BackColor = [System.Drawing.Color]::FromArgb(231, 76, 60)
            }
        }
        else {
            $Global:CredentialLabel.Text = "Not Connected"
            $Global:CredentialLabel.ForeColor = [System.Drawing.Color]::FromArgb(231, 76, 60)
            
            if ($Global:ConnectButton) {
                $Global:ConnectButton.Text = "Connect"
                $Global:ConnectButton.BackColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
            }
        }
        $Global:CredentialLabel.Refresh()
    }
}

# PERMISSION CHECKING FUNCTIONS - THESE ARE THE NEW ADDITIONS

function Test-CredentialValidity {
    param([System.Management.Automation.PSCredential]$Credential)
    
    try {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $DomainName = $Domain.Name
        
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainName", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry)
        $Searcher.Filter = "(objectClass=user)"
        $Searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $Searcher.FindOne() | Out-Null
        
        return @{
            Valid = $true
            Message = "Credentials validated successfully"
            Username = $Credential.UserName
        }
    }
    catch {
        return @{
            Valid = $false
            Message = "Authentication failed: $($_.Exception.Message)"
            Username = $Credential.UserName
        }
    }
}

function Test-ADPermissions {
    param([System.Management.Automation.PSCredential]$Credential)
    
    $Results = @{
        HasPermission = $false
        MissingPermissions = @()
        Details = @()
    }
    
    try {
        $DC = $Script:ServerInventory | Where-Object { $_.Role -match "DC|Domain Controller|AD" } | Select-Object -First 1
        
        if (-not $DC) {
            $Results.Details += "No Domain Controllers found in inventory"
            return $Results
        }
        
        $ServerName = $DC.Name
        
        if (-not (Test-ServerConnection -ServerName $ServerName -Credential $Credential)) {
            $Results.MissingPermissions += "Cannot connect to Domain Controller: $ServerName"
            return $Results
        }
        
        $ScriptBlock = {
            $PermissionResults = @{
                CanReadAD = $false
                CanReadGPO = $false
                CanReadReplication = $false
                Groups = @()
            }
            
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                
                try {
                    Get-ADUser -Filter * -ResultSetSize 1 -ErrorAction Stop | Out-Null
                    $PermissionResults.CanReadAD = $true
                }
                catch {
                    $PermissionResults.CanReadAD = $false
                }
                
                try {
                    Get-GPO -All -ErrorAction Stop | Select-Object -First 1 | Out-Null
                    $PermissionResults.CanReadGPO = $true
                }
                catch {
                    $PermissionResults.CanReadGPO = $false
                }
                
                try {
                    Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop | Out-Null
                    $PermissionResults.CanReadReplication = $true
                }
                catch {
                    $PermissionResults.CanReadReplication = $false
                }
                
                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                
                $AdminGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
                
                foreach ($GroupName in $AdminGroups) {
                    try {
                        $GroupObj = Get-ADGroup -Filter {Name -eq $GroupName} -ErrorAction SilentlyContinue
                        if ($GroupObj) {
                            $IsMember = Get-ADGroupMember -Identity $GroupObj -Recursive -ErrorAction SilentlyContinue | 
                                Where-Object { $_.SamAccountName -eq $CurrentUser.Name.Split('\')[-1] }
                            if ($IsMember) {
                                $PermissionResults.Groups += $GroupName
                            }
                        }
                    }
                    catch {}
                }
                
            }
            catch {
                $PermissionResults.Error = $_.Exception.Message
            }
            
            return $PermissionResults
        }
        
        $PermCheck = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential
        
        if ($PermCheck.Success -and $PermCheck.Data) {
            $Data = $PermCheck.Data
            
            # STRICT REQUIREMENT: Must be in Domain Admins or Enterprise Admins
            $HasRequiredGroup = $false
            $RequiredGroups = @("Domain Admins", "Enterprise Admins")
            
            # Check if user is in ANY of the required groups
            foreach ($GroupName in $RequiredGroups) {
                if ($Data.Groups -contains $GroupName) {
                    $HasRequiredGroup = $true
                    $Results.Details += "[OK] Member of $GroupName"
                    break
                }
            }
            
            # If not in required groups, mark as failed
            if (-not $HasRequiredGroup) {
                $Results.MissingPermissions += "NOT a member of Domain Admins or Enterprise Admins"
                if ($Data.Groups.Count -gt 0) {
                    $Results.Details += "[FAIL] User groups: $($Data.Groups -join ', ') - NONE are sufficient"
                } else {
                    $Results.Details += "[FAIL] User is not in any required admin groups"
                }
            }
            
            # Check capabilities (informational only - don't affect final decision)
            if ($Data.CanReadAD) {
                $Results.Details += "[OK] Can read Active Directory objects"
            } else {
                $Results.MissingPermissions += "Cannot read Active Directory objects"
            }
            
            if ($Data.CanReadGPO) {
                $Results.Details += "[OK] Can read Group Policy Objects"
            } else {
                $Results.MissingPermissions += "Cannot read Group Policy Objects"
            }
            
            if ($Data.CanReadReplication) {
                $Results.Details += "[OK] Can read Replication data"
            } else {
                $Results.MissingPermissions += "Cannot read Replication data"
            }
            
            # FINAL DECISION: Group membership is the ONLY requirement
            $Results.HasPermission = $HasRequiredGroup
            
            if (-not $Results.HasPermission) {
                $Results.Details += ""
                $Results.Details += "BLOCKED: Must be member of Domain Admins or Enterprise Admins group"
            }
        }
        else {
            $Results.MissingPermissions += "Failed to check permissions: $($PermCheck.Error)"
        }
    }
    catch {
        $Results.MissingPermissions += "Error checking AD permissions: $($_.Exception.Message)"
    }
    
    return $Results
}

function Test-ExchangePermissions {
    param([System.Management.Automation.PSCredential]$Credential)
    
    $Results = @{
        HasPermission = $false
        MissingPermissions = @()
        Details = @()
    }
    
    try {
        $ExchServer = $Script:ServerInventory | Where-Object { $_.Role -match "Exchange" } | Select-Object -First 1
        
        if (-not $ExchServer) {
            $Results.Details += "No Exchange servers found in inventory"
            return $Results
        }
        
        $ServerName = $ExchServer.Name
        
        if (-not (Test-ServerConnection -ServerName $ServerName -Credential $Credential)) {
            $Results.MissingPermissions += "Cannot connect to Exchange Server: $ServerName"
            return $Results
        }
        
        $Session = Connect-ExchangeRemote -ServerName $ServerName -Credential $Credential
        
        if (-not $Session) {
            $Results.MissingPermissions += "Cannot establish Exchange PowerShell session"
            return $Results
        }
        
        try {
            # Check Exchange Role Group Membership FIRST
            $RequiredRoles = @("Organization Management", "View-Only Organization Management")
            $UserRoles = @()
            $HasRequiredRole = $false
            
            try {
                $CurrentUserName = $Credential.UserName.Split('\')[-1]
                $RoleGroups = Get-RoleGroup -ErrorAction SilentlyContinue
                
                foreach ($RoleGroup in $RoleGroups) {
                    $Members = Get-RoleGroupMember -Identity $RoleGroup.Name -ErrorAction SilentlyContinue
                    foreach ($Member in $Members) {
                        if ($Member.SamAccountName -eq $CurrentUserName) {
                            $UserRoles += $RoleGroup.Name
                            if ($RequiredRoles -contains $RoleGroup.Name) {
                                $HasRequiredRole = $true
                            }
                        }
                    }
                }
                
                if ($HasRequiredRole) {
                    $Results.Details += "[OK] Member of required Exchange role: $($UserRoles -join ', ')"
                } else {
                    $Results.MissingPermissions += "NOT a member of Organization Management"
                    if ($UserRoles.Count -gt 0) {
                        $Results.Details += "[INFO] User roles found: $($UserRoles -join ', ')"
                    } else {
                        $Results.Details += "[FAIL] User has no Exchange role group memberships"
                    }
                }
            }
            catch {
                $Results.MissingPermissions += "Cannot verify Exchange role group membership"
                $HasRequiredRole = $false
            }
            
            $PermTests = @{
                CanReadServers = $false
                CanReadDatabases = $false
            }
            
            try {
                Get-ExchangeServer -ErrorAction Stop | Select-Object -First 1 | Out-Null
                $PermTests.CanReadServers = $true
                $Results.Details += "[OK] Can read Exchange Server configuration"
            }
            catch {
                $Results.MissingPermissions += "Cannot read Exchange Server configuration"
            }
            
            try {
                Get-MailboxDatabase -ErrorAction Stop | Select-Object -First 1 | Out-Null
                $PermTests.CanReadDatabases = $true
                $Results.Details += "[OK] Can read Mailbox Databases"
            }
            catch {
                $Results.MissingPermissions += "Cannot read Mailbox Databases"
            }
            
            $Results.HasPermission = $HasRequiredRole -and $PermTests.CanReadServers -and $PermTests.CanReadDatabases
            
            if (-not $Results.HasPermission) {
                $Results.Details += ""
                $Results.Details += "REQUIREMENT: Must be Organization Management or View-Only Organization Management"
            }
        }
        finally {
            Disconnect-ExchangeRemote -ServerName $ServerName
        }
    }
    catch {
        $Results.MissingPermissions += "Error: $($_.Exception.Message)"
    }
    
    return $Results
}

function Test-ADFSPermissions {
    param([System.Management.Automation.PSCredential]$Credential)
    
    $Results = @{
        HasPermission = $false
        MissingPermissions = @()
        Details = @()
    }
    
    try {
        $ADFSServer = $Script:ServerInventory | Where-Object { $_.Role -match "ADFS|Federation" } | Select-Object -First 1
        
        if (-not $ADFSServer) {
            $Results.Details += "No ADFS servers found in inventory"
            return $Results
        }
        
        $ServerName = $ADFSServer.Name
        
        if (-not (Test-ServerConnection -ServerName $ServerName -Credential $Credential)) {
            $Results.MissingPermissions += "Cannot connect to ADFS Server: $ServerName"
            return $Results
        }
        
        $ScriptBlock = {
            $PermissionResults = @{
                CanReadADFS = $false
                CanReadService = $false
                IsLocalAdmin = $false
            }
            
            try {
                try {
                    Import-Module ADFS -ErrorAction Stop
                    $PermissionResults.CanReadADFS = $true
                }
                catch {
                    $PermissionResults.CanReadADFS = $false
                }
                
                try {
                    Get-Service -Name "adfssrv" -ErrorAction Stop | Out-Null
                    $PermissionResults.CanReadService = $true
                }
                catch {
                    $PermissionResults.CanReadService = $false
                }
                
                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
                $AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                $PermissionResults.IsLocalAdmin = $UserPrincipal.IsInRole($AdminRole)
            }
            catch {
                $PermissionResults.Error = $_.Exception.Message
            }
            
            return $PermissionResults
        }
        
        $PermCheck = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential
        
        if ($PermCheck.Success -and $PermCheck.Data) {
            $Data = $PermCheck.Data
            
            # PRIMARY REQUIREMENT: Must be Local Administrator
            if ($Data.IsLocalAdmin) {
                $Results.Details += "[OK] Has Local Administrator rights"
            } else {
                $Results.MissingPermissions += "NOT a Local Administrator on ADFS server"
                $Results.Details += "[FAIL] Local Administrator rights REQUIRED"
            }
            
            # Secondary checks (informational only)
            if ($Data.CanReadADFS) {
                $Results.Details += "[OK] Can access ADFS module"
            } else {
                $Results.MissingPermissions += "Cannot access ADFS PowerShell module"
            }
            
            if ($Data.CanReadService) {
                $Results.Details += "[OK] Can read ADFS Service"
            } else {
                $Results.MissingPermissions += "Cannot read ADFS Service"
            }
            
            # FINAL DECISION: Local Admin is MANDATORY
            $Results.HasPermission = $Data.IsLocalAdmin
            
            if (-not $Results.HasPermission) {
                $Results.Details += ""
                $Results.Details += "BLOCKED: Must have Local Administrator rights on ADFS servers"
            }
        }
        else {
            $Results.MissingPermissions += "Failed to check permissions"
        }
    }
    catch {
        $Results.MissingPermissions += "Error: $($_.Exception.Message)"
    }
    
    return $Results
}

function Show-PermissionCheckDialog {
    param(
        [string]$ValidationType,
        [hashtable]$PermissionResults
    )
    
    $DialogForm = New-Object System.Windows.Forms.Form
    $DialogForm.Text = "$ValidationType - Permission Check"
    $DialogForm.Size = New-Object System.Drawing.Size(700, 500)
    $DialogForm.StartPosition = "CenterParent"
    $DialogForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $DialogForm.MaximizeBox = $false
    $DialogForm.MinimizeBox = $false
    
    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Permission Validation Results"
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $TitleLabel.Size = New-Object System.Drawing.Size(660, 30)
    $DialogForm.Controls.Add($TitleLabel)
    
    $StatusPanel = New-Object System.Windows.Forms.Panel
    $StatusPanel.Location = New-Object System.Drawing.Point(20, 60)
    $StatusPanel.Size = New-Object System.Drawing.Size(660, 50)
    $StatusPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    if ($PermissionResults.HasPermission) {
        $StatusPanel.BackColor = [System.Drawing.Color]::FromArgb(212, 237, 218)
        $StatusText = "[PASS] PERMISSION CHECK PASSED"
        $StatusColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
    }
    else {
        $StatusPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 215, 218)
        $StatusText = "[FAIL] INSUFFICIENT PERMISSIONS"
        $StatusColor = [System.Drawing.Color]::FromArgb(231, 76, 60)
    }
    
    $StatusLabel = New-Object System.Windows.Forms.Label
    $StatusLabel.Text = $StatusText
    $StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $StatusLabel.ForeColor = $StatusColor
    $StatusLabel.Location = New-Object System.Drawing.Point(10, 12)
    $StatusLabel.Size = New-Object System.Drawing.Size(640, 25)
    $StatusPanel.Controls.Add($StatusLabel)
    $DialogForm.Controls.Add($StatusPanel)
    
    $DetailsBox = New-Object System.Windows.Forms.TextBox
    $DetailsBox.Multiline = $true
    $DetailsBox.ScrollBars = "Vertical"
    $DetailsBox.Location = New-Object System.Drawing.Point(20, 120)
    $DetailsBox.Size = New-Object System.Drawing.Size(660, 280)
    $DetailsBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $DetailsBox.ReadOnly = $true
    
    $DetailsText = ""
    
    if ($PermissionResults.Details.Count -gt 0) {
        $DetailsText += "PERMISSION DETAILS:`r`n"
        $DetailsText += "=" * 60 + "`r`n"
        foreach ($Detail in $PermissionResults.Details) {
            $DetailsText += "$Detail`r`n"
        }
        $DetailsText += "`r`n"
    }
    
    if ($PermissionResults.MissingPermissions.Count -gt 0) {
        $DetailsText += "MISSING PERMISSIONS:`r`n"
        $DetailsText += "=" * 60 + "`r`n"
        foreach ($Missing in $PermissionResults.MissingPermissions) {
            $DetailsText += "[X] $Missing`r`n"
        }
    }
    
    $DetailsBox.Text = $DetailsText
    $DialogForm.Controls.Add($DetailsBox)
    
    $ButtonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $ButtonPanel.Location = New-Object System.Drawing.Point(20, 410)
    $ButtonPanel.Size = New-Object System.Drawing.Size(660, 50)
    $ButtonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    
    if ($PermissionResults.HasPermission) {
        $ContinueButton = New-Object System.Windows.Forms.Button
        $ContinueButton.Text = "Continue with Validation"
        $ContinueButton.Size = New-Object System.Drawing.Size(200, 40)
        $ContinueButton.BackColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
        $ContinueButton.ForeColor = [System.Drawing.Color]::White
        $ContinueButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $ContinueButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $ContinueButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $ButtonPanel.Controls.Add($ContinueButton)
        $DialogForm.AcceptButton = $ContinueButton
    }
    
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Text = "Cancel"
    $CancelButton.Size = New-Object System.Drawing.Size(100, 40)
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(149, 165, 166)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $ButtonPanel.Controls.Add($CancelButton)
    $DialogForm.CancelButton = $CancelButton
    
    $DialogForm.Controls.Add($ButtonPanel)
    
    $Result = $DialogForm.ShowDialog()
    return ($Result -eq [System.Windows.Forms.DialogResult]::OK)
}


function Start-ValidationProgress {
    param([string]$ValidationName, [int]$TotalSteps)
    
    if ($Global:ValidationInProgress) {
        [System.Windows.Forms.MessageBox]::Show(
            "A validation is already in progress!`n`nPlease wait for the current validation to complete before starting another.",
            "Validation In Progress",
            "OK",
            "Warning"
        )
        return $false
    }
    
    $Global:ValidationInProgress = $true
    
    if ($Global:ProgressContainer) {
        $Global:ProgressContainer.Visible = $true
        
        # Reset progress
        $Global:ProgressFill.Width = 1
        $Global:ProgressFill.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        
        if ($Global:ProgressLabel) {
            $Global:ProgressLabel.Text = "0%"
        }
        
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    $Global:ProgressTotalSteps = $TotalSteps
    $Global:ProgressCurrentStep = 0
    
    Update-Status "Starting $ValidationName..."
    return $true
}

function Update-ValidationProgress {
    param([int]$CurrentStep, [string]$StatusText)
    
    $Global:ProgressCurrentStep = $CurrentStep
    
    if ($Global:ProgressFill -and $Global:ProgressContainer) {
        # Calculate percentage
        $Percentage = [math]::Round(($CurrentStep / $Global:ProgressTotalSteps) * 100)
        
        # Calculate width based on container width
        $ContainerWidth = $Global:ProgressContainer.Width
        $FillWidth = [math]::Floor(($Percentage / 100) * $ContainerWidth)
        
        # Update fill width
        $Global:ProgressFill.Width = $FillWidth
        
        # Update percentage text
        if ($Global:ProgressLabel) {
            $Global:ProgressLabel.Text = "$Percentage%"
        }
        
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    Update-Status $StatusText
}

function Complete-ValidationProgress {
    param([string]$CompletionMessage)
    
    $Global:ValidationInProgress = $false
    
    if ($Global:ProgressFill -and $Global:ProgressContainer) {
        # Fill to 100%
        $Global:ProgressFill.Width = $Global:ProgressContainer.Width
        $Global:ProgressFill.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
        
        if ($Global:ProgressLabel) {
            $Global:ProgressLabel.Text = "100%"
        }
        
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 800
        
        # Hide
        $Global:ProgressContainer.Visible = $false
        
        # Reset
        $Global:ProgressFill.Width = 1
        $Global:ProgressFill.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    }
    
    Update-Status $CompletionMessage
}

function Update-Status {
    param([string]$StatusText)
    if ($Global:StatusLabel) {
        $Global:StatusLabel.Text = $StatusText
        $Global:StatusLabel.Refresh()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Test-ServerConnection {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    try {
        $TestResult = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
        if ($TestResult) {
            $Script:ConnectionStatus[$ServerName] = @{
                Status = 'Connected'
                UseCredentials = $false
            }
            return $true
        }
    }
    catch {
        try {
            $TestResult = Test-WSMan -ComputerName $ServerName -Credential $Credential -ErrorAction Stop
            if ($TestResult) {
                $Script:ConnectionStatus[$ServerName] = @{
                    Status = 'Connected'
                    UseCredentials = $true
                }
                return $true
            }
        }
        catch {
            $Script:ConnectionStatus[$ServerName] = @{
                Status = 'Failed'
                Message = $_.Exception.Message
            }
            return $false
        }
    }
}

function Invoke-SafeRemoteCommand {
    param(
        [string]$ServerName,
        [scriptblock]$ScriptBlock,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ConnectionInfo = $Script:ConnectionStatus[$ServerName]
    if (-not $ConnectionInfo -or $ConnectionInfo.Status -ne 'Connected') {
        return @{ Success = $false; Data = $null; Error = "Not connected" }
    }
    try {
        # ALWAYS use credentials when provided - never fall back to current session
        if ($Credential) {
            $Result = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential -ErrorAction Stop
        } else {
            return @{ Success = $false; Data = $null; Error = "No credentials provided" }
        }
        return @{ Success = $true; Data = $Result; Error = $null }
    }
    catch {
        return @{ Success = $false; Data = $null; Error = $_.Exception.Message }
    }
}

function Connect-ExchangeRemote {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    if ($Script:ExchangeSessions.ContainsKey($ServerName)) {
        $Session = $Script:ExchangeSessions[$ServerName]
        if ($Session.State -eq 'Opened') { return $Session }
    }
    try {
        $ConnectionInfo = $Script:ConnectionStatus[$ServerName]
        $SessionParams = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri = "http://$ServerName/PowerShell/"
            Authentication = 'Kerberos'
            ErrorAction = 'Stop'
        }
        if ($ConnectionInfo.UseCredentials) {
            $SessionParams.Credential = $Credential
        }
        $Session = New-PSSession @SessionParams
        if ($Session) {
            Import-PSSession -Session $Session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
            $Script:ExchangeSessions[$ServerName] = $Session
            return $Session
        }
    }
    catch {
        return $null
    }
    return $null
}

function Disconnect-ExchangeRemote {
    param([string]$ServerName)
    if ($Script:ExchangeSessions.ContainsKey($ServerName)) {
        try {
            Remove-PSSession -Session $Script:ExchangeSessions[$ServerName] -ErrorAction SilentlyContinue
            $Script:ExchangeSessions.Remove($ServerName)
        } catch {}
    }
}

function New-ResultDataGrid {
    param([string]$Title)
    $DataGrid = New-Object System.Windows.Forms.DataGridView
    $DataGrid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $DataGrid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $DataGrid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::AllCells
    $DataGrid.AllowUserToAddRows = $false
    $DataGrid.AllowUserToDeleteRows = $false
    $DataGrid.ReadOnly = $true
    $DataGrid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $DataGrid.BackgroundColor = [System.Drawing.Color]::White
    $DataGrid.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
    $DataGrid.GridColor = [System.Drawing.Color]::LightGray
    $DataGrid.RowHeadersVisible = $false
    $DataGrid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    $DataGrid.EnableHeadersVisualStyles = $false
    $DataGrid.ColumnHeadersDefaultCellStyle.BackColor = $Script:Colors.GridHeader
    $DataGrid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $DataGrid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $DataGrid.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $DataGrid.ColumnHeadersHeight = 35
    return $DataGrid
}

#endregion

#region Validation Functions

function Get-ServerDetails {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    $ScriptBlock = {
        $ServerDetails = @{
            Hardware = @()
            OS = @()
            Network = @()
            Disks = @()
            Services = @()
        }
        $CS = Get-WmiObject -Class Win32_ComputerSystem
        $ServerDetails.Hardware += [PSCustomObject]@{
            Property = "Computer Name"
            Value = $CS.Name
            Details = "FQDN: $($CS.DNSHostName).$($CS.Domain)"
        }
        $ServerDetails.Hardware += [PSCustomObject]@{
            Property = "Manufacturer"
            Value = $CS.Manufacturer
            Details = "Model: $($CS.Model)"
        }
        $ServerDetails.Hardware += [PSCustomObject]@{
            Property = "Physical Processors"
            Value = $CS.NumberOfProcessors
            Details = "Logical Processors: $($CS.NumberOfLogicalProcessors)"
        }
        $ServerDetails.Hardware += [PSCustomObject]@{
            Property = "Total Physical Memory"
            Value = "$([math]::Round($CS.TotalPhysicalMemory / 1GB, 2)) GB"
            Details = "Type: $($CS.SystemType)"
        }
        $CPU = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $ServerDetails.Hardware += [PSCustomObject]@{
            Property = "Processor"
            Value = $CPU.Name
            Details = "Cores: $($CPU.NumberOfCores), Speed: $($CPU.MaxClockSpeed) MHz"
        }
        $OS = Get-WmiObject -Class Win32_OperatingSystem
        $InstallDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($OS.InstallDate)
        $LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($OS.LastBootUpTime)
        $Uptime = ((Get-Date) - $LastBoot).Days
        $ServerDetails.OS += [PSCustomObject]@{
            Property = "Operating System"
            Value = $OS.Caption
            Details = "Version: $($OS.Version)"
        }
        $ServerDetails.OS += [PSCustomObject]@{
            Property = "OS Architecture"
            Value = $OS.OSArchitecture
            Details = "Build: $($OS.BuildNumber)"
        }
        $ServerDetails.OS += [PSCustomObject]@{
            Property = "Install Date"
            Value = $InstallDate.ToString("yyyy-MM-dd HH:mm:ss")
            Details = ""
        }
        $ServerDetails.OS += [PSCustomObject]@{
            Property = "Last Boot Time"
            Value = $LastBoot.ToString("yyyy-MM-dd HH:mm:ss")
            Details = "Uptime: $Uptime days"
        }
        try {
            $TZ = Get-TimeZone -ErrorAction SilentlyContinue
            if ($TZ) {
                $ServerDetails.OS += [PSCustomObject]@{
                    Property = "Time Zone"
                    Value = $TZ.DisplayName
                    Details = "ID: $($TZ.Id)"
                }
            }
        } catch {}
        $NetAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        foreach ($Adapter in $NetAdapters) {
            $ServerDetails.Network += [PSCustomObject]@{
                Description = $Adapter.Description
                IPAddress = ($Adapter.IPAddress -join ", ")
                SubnetMask = ($Adapter.IPSubnet -join ", ")
                Gateway = if ($Adapter.DefaultIPGateway) { ($Adapter.DefaultIPGateway -join ", ") } else { "None" }
                DNS = if ($Adapter.DNSServerSearchOrder) { ($Adapter.DNSServerSearchOrder -join ", ") } else { "None" }
                MACAddress = $Adapter.MACAddress
            }
        }
        $Disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        foreach ($Disk in $Disks) {
            $TotalGB = [math]::Round($Disk.Size / 1GB, 2)
            $FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
            $UsedGB = $TotalGB - $FreeGB
            $UsagePercent = if ($TotalGB -gt 0) { [math]::Round(($UsedGB / $TotalGB) * 100, 2) } else { 0 }
            $ServerDetails.Disks += [PSCustomObject]@{
                Drive = $Disk.DeviceID
                Label = if ($Disk.VolumeName) { $Disk.VolumeName } else { "No Label" }
                FileSystem = $Disk.FileSystem
                TotalSize = "$TotalGB GB"
                UsedSpace = "$UsedGB GB"
                FreeSpace = "$FreeGB GB"
                UsagePercent = "$UsagePercent%"
                Status = if ($UsagePercent -lt 85) { "Normal" } elseif ($UsagePercent -lt 95) { "Warning" } else { "Critical" }
            }
        }
        $ServiceList = @(
            "MSExchangeADTopology","MSExchangeServiceHost","MSExchangeIS","MSExchangeTransport",
            "MSExchangeFrontEndTransport","MSExchangeTransportLogSearch","MSExchangeRPC","MSExchangeRepl",
            "MSExchangeMailboxReplication","MSExchangeDelivery","MSExchangeSubmission",
            "W3SVC","IISAdmin","WinRM","WAS"
        )
        foreach ($SvcName in $ServiceList) {
            try {
                $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
                if ($Svc) {
                    $ServerDetails.Services += [PSCustomObject]@{
                        ServiceName = $Svc.Name
                        DisplayName = $Svc.DisplayName
                        Status = $Svc.Status
                        StartType = $Svc.StartType
                        State = if ($Svc.Status -eq "Running") { "OK" } else { "Stopped" }
                    }
                }
            } catch {}
        }
        return $ServerDetails
    }
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential
    if ($Result.Success) {
        return $Result.Data
    }
    return $null
}

function Get-ServerUtilization {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    $ScriptBlock = {
        $Results = @{
            CPU = @()
            Memory = @()
            Disks = @()
        }
        try {
            $CPU = Get-WmiObject -Class Win32_Processor
            $CPULoad = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop
            $CPUUsage = [math]::Round(($CPULoad.CounterSamples | Measure-Object -Property CookedValue -Average).Average, 2)
            $Results.CPU += [PSCustomObject]@{
                Metric = "Processor"
                Value = $CPU.Name
                Status = if ($CPUUsage -lt 80) { "Normal" } else { "High" }
            }
            $Results.CPU += [PSCustomObject]@{
                Metric = "Cores / Logical"
                Value = "$($CPU.NumberOfCores) / $($CPU.NumberOfLogicalProcessors)"
                Status = ""
            }
            $Results.CPU += [PSCustomObject]@{
                Metric = "Current Usage"
                Value = "$CPUUsage%"
                Status = if ($CPUUsage -lt 80) { "Normal" } else { "High" }
            }
            $OS = Get-WmiObject -Class Win32_OperatingSystem
            $TotalMemGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
            $FreeMemGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
            $UsedMemGB = $TotalMemGB - $FreeMemGB
            $MemPercent = [math]::Round(($UsedMemGB / $TotalMemGB) * 100, 2)
            $Results.Memory += [PSCustomObject]@{
                Metric = "Total Memory"
                Value = "$TotalMemGB GB"
                Status = if ($MemPercent -lt 85) { "Normal" } else { "High" }
            }
            $Results.Memory += [PSCustomObject]@{
                Metric = "Used Memory"
                Value = "$UsedMemGB GB"
                Status = ""
            }
            $Results.Memory += [PSCustomObject]@{
                Metric = "Free Memory"
                Value = "$FreeMemGB GB"
                Status = ""
            }
            $Results.Memory += [PSCustomObject]@{
                Metric = "Usage Percentage"
                Value = "$MemPercent%"
                Status = if ($MemPercent -lt 85) { "Normal" } else { "High" }
            }
            $Disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
            foreach ($Disk in $Disks) {
                $TotalGB = [math]::Round($Disk.Size / 1GB, 2)
                $FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
                $UsedGB = $TotalGB - $FreeGB
                $UsagePercent = if ($TotalGB -gt 0) { [math]::Round(($UsedGB / $TotalGB) * 100, 2) } else { 0 }
                $Results.Disks += [PSCustomObject]@{
                    Drive = $Disk.DeviceID
                    Total = "$TotalGB GB"
                    Used = "$UsedGB GB"
                    Free = "$FreeGB GB"
                    Usage = "$UsagePercent%"
                    Status = if ($UsagePercent -lt 85) { "Normal" } elseif ($UsagePercent -lt 95) { "Warning" } else { "Critical" }
                }
            }
        }
        catch {}
        return $Results
    }
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential
    if ($Result.Success) { return $Result.Data }
    return $null
}

function Test-ExchangeComprehensive {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    $ServerData = Get-ServerDetails -ServerName $ServerName -Credential $Credential
    $Session = Connect-ExchangeRemote -ServerName $ServerName -Credential $Credential
    if (-not $Session) { return $null }
    try {
        $Results = @{
            ServerInfo = @()
            DiskInfo = @()
            NetworkAdapters = @()
            WindowsServices = @()
            AcceptedDomains = @()
            MailboxDatabases = @()
            SystemMailboxes = @()
            VirtualDirectories = @()
            Certificates = @()
            SendConnectors = @()
            DAG = @()
            InternetAccess = @()
            General = @()
        }
        if ($ServerData) {
            $Results.ServerInfo = $ServerData.Hardware + $ServerData.OS
            $Results.DiskInfo = $ServerData.Disks
            $Results.NetworkAdapters = $ServerData.Network
            $Results.WindowsServices = $ServerData.Services
        }
        try {
            $Domains = Get-AcceptedDomain -ErrorAction Stop
            foreach ($Domain in $Domains) {
                $Results.AcceptedDomains += [PSCustomObject]@{
                    DomainName = $Domain.DomainName
                    DomainType = $Domain.DomainType
                    IsDefault = if ($Domain.Default) { "Yes" } else { "No" }
                    Status = if ($Domain.DomainType -eq "Authoritative") { "OK" } else { "Check" }
                }
            }
        } catch {
            $Results.AcceptedDomains += [PSCustomObject]@{
                DomainName = "Error"
                DomainType = $_.Exception.Message
                IsDefault = ""
                Status = "Failed"
            }
        }
        try {
            $Databases = Get-MailboxDatabase -Status -ErrorAction Stop
            foreach ($DB in $Databases) {
                $ProhibitSend = if ($DB.ProhibitSendQuota) { $DB.ProhibitSendQuota } else { "Not Set" }
                $ProhibitReceive = if ($DB.ProhibitSendReceiveQuota) { $DB.ProhibitSendReceiveQuota } else { "Not Set" }
                $Warning = if ($DB.IssueWarningQuota) { $DB.IssueWarningQuota } else { "Not Set" }
                $OAB = if ($DB.OfflineAddressBook) { $DB.OfflineAddressBook.Name } else { "Not Set" }
                $Results.MailboxDatabases += [PSCustomObject]@{
                    DatabaseName = $DB.Name
                    Server = $DB.Server.Name
                    Mounted = if ($DB.Mounted) { "Yes" } else { "No" }
                    OfflineAddressBook = $OAB
                    ProhibitSendQuota = $ProhibitSend
                    ProhibitSendReceiveQuota = $ProhibitReceive
                    IssueWarningQuota = $Warning
                    Status = if ($DB.Mounted) { "OK" } else { "ERROR" }
                }
            }
        } catch {}
        try {
            $Arbitration = Get-Mailbox -Arbitration -ErrorAction SilentlyContinue
            $Monitoring = Get-Mailbox -Monitoring -ErrorAction SilentlyContinue
            $AuditLog = Get-Mailbox -AuditLog -ErrorAction SilentlyContinue
            foreach ($Mbx in $Arbitration) {
                $Results.SystemMailboxes += [PSCustomObject]@{
                    Type = "Arbitration"
                    Name = $Mbx.Name
                    Database = $Mbx.Database.Name
                    Status = "OK"
                }
            }
            foreach ($Mbx in $Monitoring) {
                $Results.SystemMailboxes += [PSCustomObject]@{
                    Type = "Monitoring"
                    Name = $Mbx.Name
                    Database = $Mbx.Database.Name
                    Status = "OK"
                }
            }
            foreach ($Mbx in $AuditLog) {
                $Results.SystemMailboxes += [PSCustomObject]@{
                    Type = "Audit Log"
                    Name = $Mbx.Name
                    Database = $Mbx.Database.Name
                    Status = "OK"
                }
            }
        } catch {}
        try {
            $OWA = Get-OwaVirtualDirectory -ErrorAction SilentlyContinue
            $EWS = Get-WebServicesVirtualDirectory -ErrorAction SilentlyContinue
            $EAS = Get-ActiveSyncVirtualDirectory -ErrorAction SilentlyContinue
            $AutoD = Get-AutodiscoverVirtualDirectory -ErrorAction SilentlyContinue
            foreach ($VDir in $OWA) {
                $Results.VirtualDirectories += [PSCustomObject]@{
                    Type = "OWA"
                    Name = $VDir.Name
                    InternalURL = $VDir.InternalUrl
                    ExternalURL = $VDir.ExternalUrl
                    Status = if ($VDir.InternalUrl -and $VDir.ExternalUrl) { "OK" } else { "Check URLs" }
                }
            }
            foreach ($VDir in $EWS) {
                $Results.VirtualDirectories += [PSCustomObject]@{
                    Type = "EWS"
                    Name = $VDir.Name
                    InternalURL = $VDir.InternalUrl
                    ExternalURL = $VDir.ExternalUrl
                    Status = if ($VDir.InternalUrl -and $VDir.ExternalUrl) { "OK" } else { "Check URLs" }
                }
            }
            foreach ($VDir in $EAS) {
                $Results.VirtualDirectories += [PSCustomObject]@{
                    Type = "ActiveSync"
                    Name = $VDir.Name
                    InternalURL = $VDir.InternalUrl
                    ExternalURL = $VDir.ExternalUrl
                    Status = if ($VDir.InternalUrl -and $VDir.ExternalUrl) { "OK" } else { "Check URLs" }
                }
            }
            foreach ($VDir in $AutoD) {
                $Results.VirtualDirectories += [PSCustomObject]@{
                    Type = "Autodiscover"
                    Name = $VDir.Name
                    InternalURL = $VDir.InternalUrl
                    ExternalURL = $VDir.ExternalUrl
                    Status = if ($VDir.InternalUrl) { "OK" } else { "Check URLs" }
                }
            }
        } catch {}
        try {
            $Certs = Get-ExchangeCertificate -ErrorAction SilentlyContinue
            foreach ($Cert in $Certs) {
                $DaysToExpire = ($Cert.NotAfter - (Get-Date)).Days
                $Status = if ($DaysToExpire -lt 30) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                $Results.Certificates += [PSCustomObject]@{
                    Subject = $Cert.Subject
                    Thumbprint = $Cert.Thumbprint
                    NotAfter = $Cert.NotAfter
                    DaysToExpire = $DaysToExpire
                    Services = $Cert.Services
                    Status = $Status
                }
            }
        } catch {}
        try {
            $Connectors = Get-SendConnector -ErrorAction SilentlyContinue
            foreach ($Conn in $Connectors) {
                $SmartHosts = if ($Conn.SmartHosts) { ($Conn.SmartHosts -join ", ") } else { "Direct" }
                $MaxSize = if ($Conn.MaxMessageSize) { $Conn.MaxMessageSize } else { "Unlimited" }
                $Results.SendConnectors += [PSCustomObject]@{
                    Name = $Conn.Name
                    AddressSpaces = ($Conn.AddressSpaces -join ", ")
                    SmartHosts = $SmartHosts
                    MaxMessageSize = $MaxSize
                    Enabled = if ($Conn.Enabled) { "Yes" } else { "No" }
                    Status = if ($Conn.Enabled) { "OK" } else { "Disabled" }
                }
            }
        } catch {}
        try {
            $DAGs = Get-DatabaseAvailabilityGroup -ErrorAction SilentlyContinue
            foreach ($DAG in $DAGs) {
                $Members = if ($DAG.Servers) { ($DAG.Servers.Name -join ", ") } else { "None" }
                $Results.DAG += [PSCustomObject]@{
                    DAGName = $DAG.Name
                    Members = $Members
                    WitnessServer = $DAG.WitnessServer
                    Status = "OK"
                }
            }
            if ($DAGs.Count -eq 0) {
                $Results.DAG += [PSCustomObject]@{
                    DAGName = "No DAG Configured"
                    Members = ""
                    WitnessServer = ""
                    Status = "Info"
                }
            }
        } catch {}
        try {
            $ExchServer = Get-ExchangeServer -Identity $env:COMPUTERNAME -ErrorAction Stop
            $Results.General += [PSCustomObject]@{
                Property = "Exchange Version"
                Value = $ExchServer.AdminDisplayVersion
                Status = "OK"
            }
            $Results.General += [PSCustomObject]@{
                Property = "Exchange Edition"
                Value = $ExchServer.Edition
                Status = "OK"
            }
            $Results.General += [PSCustomObject]@{
                Property = "Server Role"
                Value = $ExchServer.ServerRole
                Status = "OK"
            }
        } catch {}
        try {
            $TransportConfig = Get-TransportConfig -ErrorAction SilentlyContinue
            $Results.General += [PSCustomObject]@{
                Property = "Max Send Size"
                Value = $TransportConfig.MaxSendSize
                Status = "OK"
            }
            $Results.General += [PSCustomObject]@{
                Property = "Max Receive Size"
                Value = $TransportConfig.MaxReceiveSize
                Status = "OK"
            }
        } catch {}
        try {
            $HybridConfig = Get-HybridConfiguration -ErrorAction SilentlyContinue
            if ($HybridConfig) {
                $Results.General += [PSCustomObject]@{
                    Property = "Hybrid Configuration"
                    Value = "Enabled"
                    Status = "OK"
                }
            } else {
                $Results.General += [PSCustomObject]@{
                    Property = "Hybrid Configuration"
                    Value = "Not Configured"
                    Status = "Info"
                }
            }
        } catch {}
        try {
            $InternetTest = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "Internet Connectivity"
                Result = if ($InternetTest) { "HAS INTERNET ACCESS" } else { "No Internet (Compliant)" }
                Status = if ($InternetTest) { "SECURITY RISK" } else { "OK" }
            }
        } catch {
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "Internet Connectivity"
                Result = "No Internet (Compliant)"
                Status = "OK"
            }
        }
        return $Results
    }
    catch {
        return $null
    }
    finally {
        Disconnect-ExchangeRemote -ServerName $ServerName
    }
}

function Test-ActiveDirectoryComprehensive {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    
    $ScriptBlock = {
        $Results = @{
            Replication = @()
            GPOs = @()
            ServiceAccounts = @()
            AdminAccounts = @()
            OUStructure = @()
            AccountDescriptions = @()
            Groups = @()
            ADFeatures = @()
            NTPPolicy = @()
            SecurityLogs = @()
            SitesAndSubnets = @()
            DNSForwarders = @()
            AutomaticUpdates = @()
            SubnetsInSites = @()
            InternetAccess = @()
        }
        
        # Import AD Module
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            return @{ Error = "Active Directory module not available: $($_.Exception.Message)" }
        }
        
        # 1. Verify Replication Health
        try {
            $ReplSummary = Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop
            foreach ($Repl in $ReplSummary) {
                $LastRepl = $Repl.LastReplicationSuccess
                $TimeSince = ((Get-Date) - $LastRepl).TotalMinutes
                $Status = if ($TimeSince -lt 60) { "OK" } elseif ($TimeSince -lt 180) { "Warning" } else { "Critical" }
                
                $Results.Replication += [PSCustomObject]@{
                    Partner = $Repl.Partner
                    Partition = $Repl.Partition
                    LastSuccess = $LastRepl.ToString("yyyy-MM-dd HH:mm:ss")
                    MinutesAgo = [math]::Round($TimeSince, 2)
                    ConsecutiveFailures = $Repl.ConsecutiveReplicationFailures
                    Status = $Status
                }
            }
        }
        catch {
            $Results.Replication += [PSCustomObject]@{
                Partner = "Error"
                Partition = $_.Exception.Message
                LastSuccess = ""
                MinutesAgo = 0
                ConsecutiveFailures = 0
                Status = "Failed"
            }
        }
        
        # 2. Display All GPOs in Domain
        try {
            $GPOList = Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName
            
            if ($GPOList) {
                foreach ($GPO in $GPOList) {
                    # Get GPO links
                    $GPOReport = [xml](Get-GPOReport -Guid $GPO.Id -ReportType Xml -ErrorAction SilentlyContinue)
                    $LinksTo = $GPOReport.GPO.LinksTo.SOMPath -join "; "
                    if (-not $LinksTo) { $LinksTo = "Not Linked" }
                    
                    # Determine status
                    $GPOStatus = if ($GPO.GpoStatus -eq "AllSettingsEnabled") { "Enabled" } 
                                elseif ($GPO.GpoStatus -eq "AllSettingsDisabled") { "Disabled" }
                                elseif ($GPO.GpoStatus -eq "UserSettingsDisabled") { "User Disabled" }
                                elseif ($GPO.GpoStatus -eq "ComputerSettingsDisabled") { "Computer Disabled" }
                                else { $GPO.GpoStatus }
                    
                    $Results.GPOs += [PSCustomObject]@{
                        GPOName = $GPO.DisplayName
                        Created = $GPO.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                        Modified = $GPO.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")
                        LinkedTo = $LinksTo
                        GPOStatus = $GPOStatus
                        Owner = $GPO.Owner
                        Status = if ($GPOStatus -match "Enabled") { "Active" } elseif ($LinksTo -eq "Not Linked") { "Unlinked" } else { "Check" }
                    }
                }
                
                # Add summary row
                $LinkedGPOs = ($GPOList | Where-Object { 
                    $Report = [xml](Get-GPOReport -Guid $_.Id -ReportType Xml -ErrorAction SilentlyContinue)
                    $Report.GPO.LinksTo.SOMPath 
                }).Count
                
                $Results.GPOs += [PSCustomObject]@{
                    GPOName = "SUMMARY"
                    Created = ""
                    Modified = ""
                    LinkedTo = ""
                    GPOStatus = ""
                    Owner = ""
                    Status = "Total: $($GPOList.Count) | Linked: $LinkedGPOs | Unlinked: $($GPOList.Count - $LinkedGPOs)"
                }
            }
            else {
                $Results.GPOs += [PSCustomObject]@{
                    GPOName = "No GPOs Found"
                    Created = ""
                    Modified = ""
                    LinkedTo = ""
                    GPOStatus = ""
                    Owner = ""
                    Status = "Warning"
                }
            }
        }
        catch {
            $Results.GPOs += [PSCustomObject]@{
                GPOName = "Error retrieving GPOs"
                Created = ""
                Modified = ""
                LinkedTo = $_.Exception.Message
                GPOStatus = ""
                Owner = ""
                Status = "Failed"
            }
        }
        
        # 3. Verify Service Accounts with RDP Deny Group
        try {
            $ServiceAccounts = Get-ADUser -Filter {Name -like "svc*" -or Name -like "*service*"} -Properties MemberOf, Description -ErrorAction Stop
            $RDPDenyGroup = Get-ADGroup -Filter {Name -like "*Deny*RDP*" -or Name -like "*Remote Desktop*Deny*"} -ErrorAction SilentlyContinue
            
            if ($ServiceAccounts) {
                foreach ($Acct in $ServiceAccounts) {
                    $InRDPDeny = if ($RDPDenyGroup -and $Acct.MemberOf -contains $RDPDenyGroup.DistinguishedName) { "Yes" } else { "No" }
                    $Status = if ($InRDPDeny -eq "Yes") { "OK" } else { "Check Required" }
                    
                    $Results.ServiceAccounts += [PSCustomObject]@{
                        AccountName = $Acct.SamAccountName
                        Enabled = $Acct.Enabled
                        Description = if ($Acct.Description) { $Acct.Description } else { "No Description" }
                        InRDPDenyGroup = $InRDPDeny
                        Status = $Status
                    }
                }
            }
            else {
                $Results.ServiceAccounts += [PSCustomObject]@{
                    AccountName = "No service accounts found"
                    Enabled = ""
                    Description = ""
                    InRDPDenyGroup = ""
                    Status = "Info"
                }
            }
        }
        catch {
            $Results.ServiceAccounts += [PSCustomObject]@{
                AccountName = "Error"
                Enabled = ""
                Description = $_.Exception.Message
                InRDPDenyGroup = ""
                Status = "Failed"
            }
        }
        
        # 4. Verify Admin Accounts
        try {
            $RequiredAdmins = @("NN-PAM01", "NN-PAM02", "NN-PATCH")
            foreach ($AdminName in $RequiredAdmins) {
                try {
                    $Admin = Get-ADUser -Identity $AdminName -Properties Description, Enabled -ErrorAction Stop
                    $Results.AdminAccounts += [PSCustomObject]@{
                        AccountName = $Admin.SamAccountName
                        Enabled = $Admin.Enabled
                        Description = if ($Admin.Description) { $Admin.Description } else { "No Description" }
                        Status = if ($Admin.Enabled -and $Admin.Description) { "OK" } elseif ($Admin.Enabled) { "Missing Description" } else { "Disabled" }
                    }
                }
                catch {
                    $Results.AdminAccounts += [PSCustomObject]@{
                        AccountName = $AdminName
                        Enabled = "N/A"
                        Description = "Account Not Found"
                        Status = "Missing"
                    }
                }
            }
        }
        catch {
            $Results.AdminAccounts += [PSCustomObject]@{
                AccountName = "Error"
                Enabled = ""
                Description = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 5. Display Current OU Structure
        try {
            $Domain = (Get-ADDomain).DistinguishedName
            $AllOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $Domain -Properties CanonicalName, Created, Description -ErrorAction Stop | Sort-Object CanonicalName
            
            if ($AllOUs) {
                foreach ($OU in $AllOUs) {
                    # Count objects in each OU
                    $UserCount = (Get-ADUser -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue).Count
                    $ComputerCount = (Get-ADComputer -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue).Count
                    $GroupCount = (Get-ADGroup -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue).Count
                    
                    $Results.OUStructure += [PSCustomObject]@{
                        OUName = $OU.Name
                        CanonicalName = $OU.CanonicalName
                        Created = $OU.Created.ToString("yyyy-MM-dd HH:mm:ss")
                        Users = $UserCount
                        Computers = $ComputerCount
                        Groups = $GroupCount
                        Description = if ($OU.Description) { $OU.Description } else { "" }
                        Status = "Active"
                    }
                }
                
                # Add summary
                $Results.OUStructure += [PSCustomObject]@{
                    OUName = "TOTAL OUs in Domain"
                    CanonicalName = ""
                    Created = ""
                    Users = ($AllOUs | ForEach-Object { (Get-ADUser -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue).Count } | Measure-Object -Sum).Sum
                    Computers = ($AllOUs | ForEach-Object { (Get-ADComputer -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue).Count } | Measure-Object -Sum).Sum
                    Groups = ($AllOUs | ForEach-Object { (Get-ADGroup -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue).Count } | Measure-Object -Sum).Sum
                    Description = "$($AllOUs.Count) OUs Total"
                    Status = "Summary"
                }
            }
            else {
                $Results.OUStructure += [PSCustomObject]@{
                    OUName = "No OUs Found"
                    CanonicalName = ""
                    Created = ""
                    Users = 0
                    Computers = 0
                    Groups = 0
                    Description = ""
                    Status = "Info"
                }
            }
        }
        catch {
            $Results.OUStructure += [PSCustomObject]@{
                OUName = "Error"
                CanonicalName = ""
                Created = ""
                Users = 0
                Computers = 0
                Groups = 0
                Description = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 6. Verify Account Descriptions (Admin and Service Accounts)
        try {
            $AllAdminAccounts = Get-ADUser -Filter {AdminCount -eq 1} -Properties Description -ErrorAction Stop
            $MissingDesc = $AllAdminAccounts | Where-Object { -not $_.Description }
            
            $Results.AccountDescriptions += [PSCustomObject]@{
                Check = "Total Admin Accounts"
                Count = $AllAdminAccounts.Count
                Details = ""
                Status = "Info"
            }
            
            $Results.AccountDescriptions += [PSCustomObject]@{
                Check = "Admin Accounts with Description"
                Count = ($AllAdminAccounts.Count - $MissingDesc.Count)
                Details = ""
                Status = "OK"
            }
            
            $Results.AccountDescriptions += [PSCustomObject]@{
                Check = "Admin Accounts WITHOUT Description"
                Count = $MissingDesc.Count
                Details = if ($MissingDesc) { ($MissingDesc.SamAccountName -join ", ") } else { "All have descriptions" }
                Status = if ($MissingDesc.Count -eq 0) { "OK" } else { "Warning" }
            }
        }
        catch {
            $Results.AccountDescriptions += [PSCustomObject]@{
                Check = "Error"
                Count = 0
                Details = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 7. Verify Group Accounts
        try {
            $Groups = Get-ADGroup -Filter * -Properties Description, ManagedBy -ErrorAction Stop
            $Results.Groups += [PSCustomObject]@{
                Check = "Total Groups in Domain"
                Count = $Groups.Count
                Details = ""
                Status = "Info"
            }
            
            $GroupsWithoutDesc = $Groups | Where-Object { -not $_.Description }
            $Results.Groups += [PSCustomObject]@{
                Check = "Groups without Description"
                Count = $GroupsWithoutDesc.Count
                Details = if ($GroupsWithoutDesc.Count -lt 10) { ($GroupsWithoutDesc.Name -join ", ") } else { "Too many to list" }
                Status = if ($GroupsWithoutDesc.Count -eq 0) { "OK" } else { "Warning" }
            }
            
            $EmptyGroups = $Groups | Where-Object { (Get-ADGroupMember $_ -ErrorAction SilentlyContinue).Count -eq 0 }
            $Results.Groups += [PSCustomObject]@{
                Check = "Empty Groups"
                Count = $EmptyGroups.Count
                Details = if ($EmptyGroups.Count -lt 10) { ($EmptyGroups.Name -join ", ") } else { "Too many to list" }
                Status = "Info"
            }
        }
        catch {
            $Results.Groups += [PSCustomObject]@{
                Check = "Error"
                Count = 0
                Details = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 8. Verify AD Recycle Bin
        try {
            $RecycleBin = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"} -ErrorAction Stop
            $IsEnabled = if ($RecycleBin.EnabledScopes.Count -gt 0) { "Enabled" } else { "Disabled" }
            
            $Results.ADFeatures += [PSCustomObject]@{
                Feature = "AD Recycle Bin"
                Status = $IsEnabled
                EnabledDate = if ($RecycleBin.EnabledScopes) { "Enabled" } else { "N/A" }
                Result = if ($IsEnabled -eq "Enabled") { "OK" } else { "Not Enabled" }
            }
        }
        catch {
            $Results.ADFeatures += [PSCustomObject]@{
                Feature = "AD Recycle Bin"
                Status = "Error"
                EnabledDate = $_.Exception.Message
                Result = "Failed"
            }
        }
        
        # 9. Verify NTP Policy
        try {
            $GPOs = Get-GPO -All -ErrorAction Stop
            $NTPPolicy = $GPOs | Where-Object { $_.DisplayName -like "*NTP*" -or $_.DisplayName -like "*Time*" }
            
            if ($NTPPolicy) {
                foreach ($Policy in $NTPPolicy) {
                    $Results.NTPPolicy += [PSCustomObject]@{
                        PolicyName = $Policy.DisplayName
                        Created = $Policy.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                        Status = "OK"
                    }
                }
            }
            else {
                $Results.NTPPolicy += [PSCustomObject]@{
                    PolicyName = "No NTP Policy Found"
                    Created = ""
                    Status = "Warning"
                }
            }
            
            # Check actual W32Time service config
            $W32Time = w32tm /query /status 2>&1
            $Results.NTPPolicy += [PSCustomObject]@{
                PolicyName = "W32Time Service Status"
                Created = ""
                Status = if ($LASTEXITCODE -eq 0) { "Running" } else { "Check Required" }
            }
        }
        catch {
            $Results.NTPPolicy += [PSCustomObject]@{
                PolicyName = "Error"
                Created = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 10. Verify Security Log Size on DCs
        try {
            $SecurityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
            $LogSizeGB = [math]::Round($SecurityLog.MaximumSizeInBytes / 1GB, 2)
            $Status = if ($LogSizeGB -ge 10) { "OK" } else { "Too Small" }
            
            $Results.SecurityLogs += [PSCustomObject]@{
                LogName = "Security"
                MaxSize = "$LogSizeGB GB"
                Required = "10 GB"
                CurrentRecords = $SecurityLog.RecordCount
                Status = $Status
            }
        }
        catch {
            $Results.SecurityLogs += [PSCustomObject]@{
                LogName = "Security"
                MaxSize = "Error"
                Required = "10 GB"
                CurrentRecords = 0
                Status = $_.Exception.Message
            }
        }
        
        # 11. Verify AD Sites and Subnets
        try {
            $Sites = Get-ADReplicationSite -Filter * -ErrorAction Stop
            $Subnets = Get-ADReplicationSubnet -Filter * -ErrorAction Stop
            
            $Results.SitesAndSubnets += [PSCustomObject]@{
                Check = "Total AD Sites"
                Count = $Sites.Count
                Details = ($Sites.Name -join ", ")
                Status = if ($Sites.Count -gt 0) { "OK" } else { "None Found" }
            }
            
            $Results.SitesAndSubnets += [PSCustomObject]@{
                Check = "Total Subnets"
                Count = $Subnets.Count
                Details = if ($Subnets.Count -lt 20) { ($Subnets.Name -join ", ") } else { "Multiple subnets configured" }
                Status = if ($Subnets.Count -gt 0) { "OK" } else { "None Found" }
            }
        }
        catch {
            $Results.SitesAndSubnets += [PSCustomObject]@{
                Check = "Error"
                Count = 0
                Details = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 12. Verify DNS Forwarders
        try {
            $DNSForwarders = Get-DnsServerForwarder -ErrorAction Stop
            $RequiredForwarders = @("212.12.160.2", "212.12.160.3")
            
            foreach ($Required in $RequiredForwarders) {
                $Found = $DNSForwarders.IPAddress.IPAddressToString -contains $Required
                $Results.DNSForwarders += [PSCustomObject]@{
                    ForwarderIP = $Required
                    Configured = if ($Found) { "Yes" } else { "No" }
                    Status = if ($Found) { "OK" } else { "Missing" }
                }
            }
            
            # List all configured forwarders
            if ($DNSForwarders.IPAddress) {
                $Results.DNSForwarders += [PSCustomObject]@{
                    ForwarderIP = "All Configured Forwarders"
                    Configured = ($DNSForwarders.IPAddress.IPAddressToString -join ", ")
                    Status = "Info"
                }
            }
        }
        catch {
            $Results.DNSForwarders += [PSCustomObject]@{
                ForwarderIP = "Error"
                Configured = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 13. Verify Automatic Updates Disabled via GPO
        try {
            $GPOs = Get-GPO -All -ErrorAction Stop
            $UpdatePolicy = $GPOs | Where-Object { $_.DisplayName -like "*Update*" -or $_.DisplayName -like "*WSUS*" }
            
            if ($UpdatePolicy) {
                foreach ($Policy in $UpdatePolicy) {
                    $Results.AutomaticUpdates += [PSCustomObject]@{
                        PolicyName = $Policy.DisplayName
                        Created = $Policy.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                        Status = "Found"
                    }
                }
            }
            else {
                $Results.AutomaticUpdates += [PSCustomObject]@{
                    PolicyName = "No Update Policy Found"
                    Created = ""
                    Status = "Warning - Check Manually"
                }
            }
            
            # Check local Windows Update service
            $WUService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
            $Results.AutomaticUpdates += [PSCustomObject]@{
                PolicyName = "Windows Update Service"
                Created = ""
                Status = "$($WUService.Status) / $($WUService.StartType)"
            }
        }
        catch {
            $Results.AutomaticUpdates += [PSCustomObject]@{
                PolicyName = "Error"
                Created = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 14. Verify Subnets in AD Sites (Detailed)
        try {
            $Sites = Get-ADReplicationSite -Filter * -Properties Subnets -ErrorAction Stop
            foreach ($Site in $Sites) {
                $SubnetList = $Site.Subnets
                $Results.SubnetsInSites += [PSCustomObject]@{
                    SiteName = $Site.Name
                    SubnetCount = if ($SubnetList) { $SubnetList.Count } else { 0 }
                    Subnets = if ($SubnetList) { ($SubnetList -replace "CN=|,CN=Subnets,CN=Sites,.*" -join "; ") } else { "No subnets" }
                    Status = if ($SubnetList) { "OK" } else { "No Subnets" }
                }
            }
        }
        catch {
            $Results.SubnetsInSites += [PSCustomObject]@{
                SiteName = "Error"
                SubnetCount = 0
                Subnets = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        # 15. Verify No Internet Access
        try {
            $InternetTest = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "Internet Connectivity Test"
                Target = "8.8.8.8 (Google DNS)"
                Result = if ($InternetTest) { "HAS INTERNET ACCESS" } else { "No Internet (Compliant)" }
                Status = if ($InternetTest) { "SECURITY RISK" } else { "OK" }
            }
        }
        catch {
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "Internet Connectivity Test"
                Target = "8.8.8.8 (Google DNS)"
                Result = "No Internet (Compliant)"
                Status = "OK"
            }
        }
        
        return $Results
    }
    
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential
    if ($Result.Success) {
        return $Result.Data
    }
    return $null
}

function Test-ADFSComprehensive {
    param([string]$ServerName, [System.Management.Automation.PSCredential]$Credential)
    
    $ScriptBlock = {
        $Results = @{
            ServiceStatus = @()
            CommunicationPorts = @()
            SSLCertificates = @()
            TokenSigningCerts = @()
            ServiceAccount = @()
            MFAConfiguration = @()
            ADFSProperties = @()
            FarmInformation = @()
        }
        
        # 1. Verify ADFS Service Running
        try {
            $ADFSService = Get-Service -Name "adfssrv" -ErrorAction SilentlyContinue
            
            if ($ADFSService) {
                $Results.ServiceStatus += [PSCustomObject]@{
                    ServiceName = $ADFSService.Name
                    DisplayName = $ADFSService.DisplayName
                    Status = $ADFSService.Status
                    StartType = $ADFSService.StartType
                    Result = if ($ADFSService.Status -eq "Running") { "Service Running" } else { "Service NOT Running" }
                    StatusCode = if ($ADFSService.Status -eq "Running") { "OK" } else { "Critical" }
                }
            }
            else {
                $Results.ServiceStatus += [PSCustomObject]@{
                    ServiceName = "adfssrv"
                    DisplayName = "Active Directory Federation Services"
                    Status = "Not Found"
                    StartType = "N/A"
                    Result = "ADFS Service Not Installed"
                    StatusCode = "Error"
                }
            }
            
            # Check dependent services
            $DependentServices = @("W3SVC", "http")
            foreach ($SvcName in $DependentServices) {
                $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
                if ($Svc) {
                    $Results.ServiceStatus += [PSCustomObject]@{
                        ServiceName = $Svc.Name
                        DisplayName = $Svc.DisplayName
                        Status = $Svc.Status
                        StartType = $Svc.StartType
                        Result = if ($Svc.Status -eq "Running") { "Supporting Service Running" } else { "Service Stopped" }
                        StatusCode = if ($Svc.Status -eq "Running") { "OK" } else { "Warning" }
                    }
                }
            }
        }
        catch {
            $Results.ServiceStatus += [PSCustomObject]@{
                ServiceName = "Error"
                DisplayName = ""
                Status = ""
                StartType = ""
                Result = $_.Exception.Message
                StatusCode = "Failed"
            }
        }
        
        # 2. Verify Required Communication Ports
        try {
            $RequiredPorts = @(
                @{Port=443; Protocol="TCP"; Service="HTTPS (ADFS)"; Type="Required"},
                @{Port=80; Protocol="TCP"; Service="HTTP (Redirect)"; Type="Required"},
                @{Port=49443; Protocol="TCP"; Service="Certificate Authentication"; Type="Optional"},
                @{Port=808; Protocol="TCP"; Service="Device Registration"; Type="Optional"}
            )
            
            foreach ($PortInfo in $RequiredPorts) {
                try {
                    $Listener = Get-NetTCPConnection -LocalPort $PortInfo.Port -State Listen -ErrorAction SilentlyContinue
                    if ($Listener) {
                        $Results.CommunicationPorts += [PSCustomObject]@{
                            Port = $PortInfo.Port
                            Protocol = $PortInfo.Protocol
                            Service = $PortInfo.Service
                            Type = $PortInfo.Type
                            Status = "Listening"
                            ProcessID = $Listener[0].OwningProcess
                            Result = "OK"
                        }
                    }
                    else {
                        $Results.CommunicationPorts += [PSCustomObject]@{
                            Port = $PortInfo.Port
                            Protocol = $PortInfo.Protocol
                            Service = $PortInfo.Service
                            Type = $PortInfo.Type
                            Status = "Not Listening"
                            ProcessID = "N/A"
                            Result = if ($PortInfo.Type -eq "Required") { "Critical" } else { "Info" }
                        }
                    }
                }
                catch {
                    $Results.CommunicationPorts += [PSCustomObject]@{
                        Port = $PortInfo.Port
                        Protocol = $PortInfo.Protocol
                        Service = $PortInfo.Service
                        Type = $PortInfo.Type
                        Status = "Check Failed"
                        ProcessID = "N/A"
                        Result = "Warning"
                    }
                }
            }
            
            # Test external connectivity
            try {
                $FirewallTest = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port 443 -WarningAction SilentlyContinue -ErrorAction Stop
                $Results.CommunicationPorts += [PSCustomObject]@{
                    Port = 443
                    Protocol = "TCP"
                    Service = "External HTTPS Connectivity Test"
                    Type = "Test"
                    Status = if ($FirewallTest.TcpTestSucceeded) { "Success" } else { "Failed" }
                    ProcessID = "N/A"
                    Result = if ($FirewallTest.TcpTestSucceeded) { "OK" } else { "Warning" }
                }
            }
            catch {}
        }
        catch {
            $Results.CommunicationPorts += [PSCustomObject]@{
                Port = 0
                Protocol = ""
                Service = "Error checking ports"
                Type = ""
                Status = $_.Exception.Message
                ProcessID = ""
                Result = "Failed"
            }
        }
        
        # 3. Verify SSL Certificate on ADFS
        try {
            # Get ADFS SSL Certificate from IIS
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            
            $ADFSSite = Get-Website | Where-Object { $_.Name -like "*ADFS*" -or $_.Bindings.Collection.bindingInformation -like "*:443:*" } | Select-Object -First 1
            
            if ($ADFSSite) {
                $Binding = $ADFSSite.Bindings.Collection | Where-Object { $_.protocol -eq "https" } | Select-Object -First 1
                if ($Binding) {
                    $CertHash = $Binding.certificateHash
                    $Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $CertHash }
                    
                    if ($Cert) {
                        $DaysToExpire = ($Cert.NotAfter - (Get-Date)).Days
                        $Status = if ($DaysToExpire -lt 30) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                        
                        $Results.SSLCertificates += [PSCustomObject]@{
                            Subject = $Cert.Subject
                            Issuer = $Cert.Issuer
                            Thumbprint = $Cert.Thumbprint
                            NotBefore = $Cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                            NotAfter = $Cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                            DaysToExpire = $DaysToExpire
                            HasPrivateKey = $Cert.HasPrivateKey
                            Location = "IIS HTTPS Binding"
                            Status = $Status
                        }
                    }
                }
            }
            
            # Get all certificates from Personal store that might be used for ADFS
            $PersonalCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
                $_.Subject -like "*adfs*" -or 
                $_.Subject -like "*federation*" -or
                $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
            } | Sort-Object NotAfter -Descending
            
            foreach ($Cert in $PersonalCerts) {
                $DaysToExpire = ($Cert.NotAfter - (Get-Date)).Days
                $Status = if ($DaysToExpire -lt 30) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                
                $Results.SSLCertificates += [PSCustomObject]@{
                    Subject = $Cert.Subject
                    Issuer = $Cert.Issuer
                    Thumbprint = $Cert.Thumbprint
                    NotBefore = $Cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss")
                    NotAfter = $Cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                    DaysToExpire = $DaysToExpire
                    HasPrivateKey = $Cert.HasPrivateKey
                    Location = "Personal Store"
                    Status = $Status
                }
            }
            
            if ($Results.SSLCertificates.Count -eq 0) {
                $Results.SSLCertificates += [PSCustomObject]@{
                    Subject = "No SSL Certificates Found"
                    Issuer = ""
                    Thumbprint = ""
                    NotBefore = ""
                    NotAfter = ""
                    DaysToExpire = 0
                    HasPrivateKey = $false
                    Location = ""
                    Status = "Warning"
                }
            }
        }
        catch {
            $Results.SSLCertificates += [PSCustomObject]@{
                Subject = "Error"
                Issuer = $_.Exception.Message
                Thumbprint = ""
                NotBefore = ""
                NotAfter = ""
                DaysToExpire = 0
                HasPrivateKey = $false
                Location = ""
                Status = "Failed"
            }
        }
        
        # 4. Verify Token Signing Certificate
        try {
            # Try to load ADFS module
            try {
                Import-Module ADFS -ErrorAction Stop
                $ADFSInstalled = $true
            }
            catch {
                $ADFSInstalled = $false
            }
            
            if ($ADFSInstalled) {
                # Get ADFS certificates using ADFS cmdlets
                try {
                    $TokenSigningCerts = Get-AdfsCertificate -CertificateType Token-Signing -ErrorAction Stop
                    
                    foreach ($Cert in $TokenSigningCerts) {
                        $CertObj = Get-Item "Cert:\LocalMachine\My\$($Cert.Thumbprint)" -ErrorAction SilentlyContinue
                        
                        if ($CertObj) {
                            $DaysToExpire = ($CertObj.NotAfter - (Get-Date)).Days
                            $Status = if ($DaysToExpire -lt 30) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                            
                            $Results.TokenSigningCerts += [PSCustomObject]@{
                                CertificateType = "Token-Signing"
                                Subject = $CertObj.Subject
                                Thumbprint = $Cert.Thumbprint
                                IsPrimary = $Cert.IsPrimary
                                NotAfter = $CertObj.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                                DaysToExpire = $DaysToExpire
                                AutoRollover = if ($Cert.CertificateType) { "Enabled" } else { "Check Config" }
                                Status = $Status
                            }
                        }
                    }
                    
                    # Get Token-Decrypting certificates
                    $TokenDecryptCerts = Get-AdfsCertificate -CertificateType Token-Decrypting -ErrorAction SilentlyContinue
                    foreach ($Cert in $TokenDecryptCerts) {
                        $CertObj = Get-Item "Cert:\LocalMachine\My\$($Cert.Thumbprint)" -ErrorAction SilentlyContinue
                        
                        if ($CertObj) {
                            $DaysToExpire = ($CertObj.NotAfter - (Get-Date)).Days
                            $Status = if ($DaysToExpire -lt 30) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                            
                            $Results.TokenSigningCerts += [PSCustomObject]@{
                                CertificateType = "Token-Decrypting"
                                Subject = $CertObj.Subject
                                Thumbprint = $Cert.Thumbprint
                                IsPrimary = $Cert.IsPrimary
                                NotAfter = $CertObj.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                                DaysToExpire = $DaysToExpire
                                AutoRollover = if ($Cert.CertificateType) { "Enabled" } else { "Check Config" }
                                Status = $Status
                            }
                        }
                    }
                }
                catch {
                    $Results.TokenSigningCerts += [PSCustomObject]@{
                        CertificateType = "Error"
                        Subject = $_.Exception.Message
                        Thumbprint = ""
                        IsPrimary = $false
                        NotAfter = ""
                        DaysToExpire = 0
                        AutoRollover = ""
                        Status = "Failed"
                    }
                }
            }
            else {
                # ADFS module not available, check certificate store manually
                $TokenCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
                    $_.Subject -like "*ADFS Signing*" -or 
                    $_.FriendlyName -like "*Token*" -or
                    $_.Subject -like "*Token Signing*"
                }
                
                if ($TokenCerts) {
                    foreach ($Cert in $TokenCerts) {
                        $DaysToExpire = ($Cert.NotAfter - (Get-Date)).Days
                        $Status = if ($DaysToExpire -lt 30) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                        
                        $Results.TokenSigningCerts += [PSCustomObject]@{
                            CertificateType = "Token Signing (Manual Check)"
                            Subject = $Cert.Subject
                            Thumbprint = $Cert.Thumbprint
                            IsPrimary = "Unknown"
                            NotAfter = $Cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
                            DaysToExpire = $DaysToExpire
                            AutoRollover = "Check Manually"
                            Status = $Status
                        }
                    }
                }
                else {
                    $Results.TokenSigningCerts += [PSCustomObject]@{
                        CertificateType = "Token Signing"
                        Subject = "No token signing certificates found"
                        Thumbprint = ""
                        IsPrimary = $false
                        NotAfter = ""
                        DaysToExpire = 0
                        AutoRollover = ""
                        Status = "Warning"
                    }
                }
            }
        }
        catch {
            $Results.TokenSigningCerts += [PSCustomObject]@{
                CertificateType = "Error"
                Subject = $_.Exception.Message
                Thumbprint = ""
                IsPrimary = $false
                NotAfter = ""
                DaysToExpire = 0
                AutoRollover = ""
                Status = "Failed"
            }
        }
        
        # 5. Verify ADFS Service Account
        try {
            $ADFSService = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq "adfssrv" }
            
            if ($ADFSService) {
                $ServiceAccount = $ADFSService.StartName
                
                # Check if it's a managed service account
                $IsMSA = $ServiceAccount -like "*$"
                $AccountType = if ($IsMSA) { "Managed Service Account (gMSA)" } elseif ($ServiceAccount -eq "LocalSystem") { "Local System" } else { "Domain Account" }
                
                $Results.ServiceAccount += [PSCustomObject]@{
                    Service = "ADFS Service"
                    Account = $ServiceAccount
                    AccountType = $AccountType
                    Recommendation = if ($IsMSA) { "Best Practice - Using gMSA" } elseif ($ServiceAccount -eq "LocalSystem") { "Not Recommended" } else { "Standard Domain Account" }
                    Status = if ($IsMSA) { "OK" } elseif ($ServiceAccount -eq "LocalSystem") { "Warning" } else { "OK" }
                }
                
                # Try to get more account details if it's a domain account
                if (-not $IsMSA -and $ServiceAccount -ne "LocalSystem") {
                    try {
                        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                        $Username = $ServiceAccount -replace ".*\\"
                        $ADUser = Get-ADUser -Identity $Username -Properties PasswordLastSet, PasswordNeverExpires, Enabled -ErrorAction SilentlyContinue
                        
                        if ($ADUser) {
                            $Results.ServiceAccount += [PSCustomObject]@{
                                Service = "Account Details"
                                Account = $ADUser.SamAccountName
                                AccountType = "Enabled: $($ADUser.Enabled)"
                                Recommendation = "Password Last Set: $($ADUser.PasswordLastSet)"
                                Status = if ($ADUser.Enabled) { "OK" } else { "Critical" }
                            }
                        }
                    }
                    catch {}
                }
            }
            else {
                $Results.ServiceAccount += [PSCustomObject]@{
                    Service = "ADFS Service"
                    Account = "Service Not Found"
                    AccountType = ""
                    Recommendation = ""
                    Status = "Error"
                }
            }
        }
        catch {
            $Results.ServiceAccount += [PSCustomObject]@{
                Service = "Error"
                Account = $_.Exception.Message
                AccountType = ""
                Recommendation = ""
                Status = "Failed"
            }
        }
        
        # 6. Verify MFA Configuration
        try {
            # Try to load ADFS module
            try {
                Import-Module ADFS -ErrorAction Stop
                $ADFSInstalled = $true
            }
            catch {
                $ADFSInstalled = $false
            }
            
            if ($ADFSInstalled) {
                # Get ADFS Properties for MFA settings
                try {
                    $ADFSProperties = Get-AdfsProperties -ErrorAction Stop
                    
                    # Check authentication providers
                    $GlobalAuthProviders = Get-AdfsGlobalAuthenticationPolicy -ErrorAction SilentlyContinue
                    
                    if ($GlobalAuthProviders) {
                        $PrimaryExternal = $GlobalAuthProviders.PrimaryExtranetAuthenticationProvider -join ", "
                        $SecondaryExternal = $GlobalAuthProviders.AdditionalAuthenticationProvider -join ", "
                        
                        $Results.MFAConfiguration += [PSCustomObject]@{
                            Setting = "Primary Extranet Auth Provider"
                            Value = if ($PrimaryExternal) { $PrimaryExternal } else { "Forms Authentication" }
                            Type = "Authentication"
                            Status = if ($PrimaryExternal) { "Configured" } else { "Default" }
                        }
                        
                        $Results.MFAConfiguration += [PSCustomObject]@{
                            Setting = "Additional Auth Provider (MFA)"
                            Value = if ($SecondaryExternal) { $SecondaryExternal } else { "Not Configured" }
                            Type = "MFA"
                            Status = if ($SecondaryExternal) { "MFA Enabled" } else { "No MFA" }
                        }
                    }
                    
                    # Check for Azure MFA
                    $AuthProviders = Get-AdfsAuthenticationProvider -ErrorAction SilentlyContinue
                    $AzureMFA = $AuthProviders | Where-Object { $_.Name -like "*Azure*" -or $_.Name -like "*MFA*" }
                    
                    if ($AzureMFA) {
                        foreach ($Provider in $AzureMFA) {
                            $Results.MFAConfiguration += [PSCustomObject]@{
                                Setting = "MFA Provider Found"
                                Value = $Provider.Name
                                Type = "Azure MFA / Third-Party"
                                Status = "Configured"
                            }
                        }
                    }
                    else {
                        $Results.MFAConfiguration += [PSCustomObject]@{
                            Setting = "Azure MFA / Third-Party Provider"
                            Value = "Not Detected"
                            Type = "MFA Provider"
                            Status = "Check Manually"
                        }
                    }
                    
                    # Check certificate authentication (can be used for MFA)
                    $CertAuthEnabled = $ADFSProperties.CertificateAuthenticationEnabled
                    $Results.MFAConfiguration += [PSCustomObject]@{
                        Setting = "Certificate Authentication"
                        Value = if ($CertAuthEnabled) { "Enabled" } else { "Disabled" }
                        Type = "Authentication Method"
                        Status = if ($CertAuthEnabled) { "OK" } else { "Info" }
                    }
                    
                    # Device authentication
                    $DeviceAuthEnabled = $ADFSProperties.DeviceAuthenticationEnabled
                    $Results.MFAConfiguration += [PSCustomObject]@{
                        Setting = "Device Authentication"
                        Value = if ($DeviceAuthEnabled) { "Enabled" } else { "Disabled" }
                        Type = "Authentication Method"
                        Status = if ($DeviceAuthEnabled) { "OK" } else { "Info" }
                    }
                }
                catch {
                    $Results.MFAConfiguration += [PSCustomObject]@{
                        Setting = "Error retrieving MFA config"
                        Value = $_.Exception.Message
                        Type = ""
                        Status = "Failed"
                    }
                }
            }
            else {
                $Results.MFAConfiguration += [PSCustomObject]@{
                    Setting = "ADFS Module Not Available"
                    Value = "Cannot check MFA configuration without ADFS PowerShell module"
                    Type = "Module Missing"
                    Status = "Warning"
                }
            }
            
            # Manual check for Ceitcon or other MFA providers by registry or files
            $MFAProviderPaths = @(
                "C:\Program Files\Ceitcon",
                "C:\Program Files\Azure MFA",
                "C:\Program Files (x86)\Ceitcon"
            )
            
            foreach ($Path in $MFAProviderPaths) {
                if (Test-Path $Path) {
                    $ProviderName = Split-Path $Path -Leaf
                    $Results.MFAConfiguration += [PSCustomObject]@{
                        Setting = "MFA Provider Installation Detected"
                        Value = $ProviderName
                        Type = "File System Check"
                        Status = "Found"
                    }
                }
            }
        }
        catch {
            $Results.MFAConfiguration += [PSCustomObject]@{
                Setting = "Error"
                Value = $_.Exception.Message
                Type = ""
                Status = "Failed"
            }
        }
        
        # 7. Get ADFS Properties and Farm Information
        try {
            try {
                Import-Module ADFS -ErrorAction Stop
                $ADFSInstalled = $true
            }
            catch {
                $ADFSInstalled = $false
            }
            
            if ($ADFSInstalled) {
                $ADFSProperties = Get-AdfsProperties -ErrorAction SilentlyContinue
                
                if ($ADFSProperties) {
                    $Results.ADFSProperties += [PSCustomObject]@{
                        Property = "ADFS Display Name"
                        Value = $ADFSProperties.DisplayName
                        Status = "Info"
                    }
                    
                    $Results.ADFSProperties += [PSCustomObject]@{
                        Property = "Host Name"
                        Value = $ADFSProperties.HostName
                        Status = "Info"
                    }
                    
                    $Results.ADFSProperties += [PSCustomObject]@{
                        Property = "Identifier"
                        Value = $ADFSProperties.Identifier
                        Status = "Info"
                    }
                    
                    $Results.ADFSProperties += [PSCustomObject]@{
                        Property = "Certificate Sharing Container"
                        Value = $ADFSProperties.CertificateSharingContainer
                        Status = "Info"
                    }
                    
                    $Results.ADFSProperties += [PSCustomObject]@{
                        Property = "Auto Certificate Rollover"
                        Value = $ADFSProperties.AutoCertificateRollover
                        Status = if ($ADFSProperties.AutoCertificateRollover) { "OK" } else { "Warning" }
                    }
                }
                
                # Get Farm Information
                $SyncProperties = Get-AdfsSyncProperties -ErrorAction SilentlyContinue
                if ($SyncProperties) {
                    $Results.FarmInformation += [PSCustomObject]@{
                        Property = "Role"
                        Value = $SyncProperties.Role
                        Details = ""
                        Status = "Info"
                    }
                    
                    $Results.FarmInformation += [PSCustomObject]@{
                        Property = "Primary Computer"
                        Value = $SyncProperties.PrimaryComputerName
                        Details = ""
                        Status = "Info"
                    }
                    
                    $Results.FarmInformation += [PSCustomObject]@{
                        Property = "Polling Interval"
                        Value = $SyncProperties.PollDuration
                        Details = "seconds"
                        Status = "Info"
                    }
                }
                
                # Get farm nodes
                try {
                    $FarmNodes = Get-AdfsFarmInformation -ErrorAction SilentlyContinue
                    if ($FarmNodes) {
                        $Results.FarmInformation += [PSCustomObject]@{
                            Property = "Farm Behavior Level"
                            Value = $FarmNodes.CurrentFarmBehavior
                            Details = ""
                            Status = "Info"
                        }
                        
                        $Results.FarmInformation += [PSCustomObject]@{
                            Property = "Farm Nodes Count"
                            Value = $FarmNodes.FarmNodes.Count
                            Details = ($FarmNodes.FarmNodes -join ", ")
                            Status = "Info"
                        }
                    }
                }
                catch {}
            }
            else {
                $Results.ADFSProperties += [PSCustomObject]@{
                    Property = "ADFS Module"
                    Value = "Not Available"
                    Status = "Warning"
                }
            }
        }
        catch {
            $Results.ADFSProperties += [PSCustomObject]@{
                Property = "Error"
                Value = $_.Exception.Message
                Status = "Failed"
            }
        }
        
        return $Results
    }
    
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential
    if ($Result.Success) {
        return $Result.Data
    }
    return $null
}

#endregion

#region Button Handlers
#region Button Handlers

function Show-UtilizationResults {
    # Check if user is connected first
    if (-not $Script:Credential) {
        [System.Windows.Forms.MessageBox]::Show(
            "You must connect with credentials first!`n`nClick the 'Connect' button to authenticate before running validations.",
            "Authentication Required",
            "OK",
            "Warning"
        )
        return
    }
    
    # CHECK PERMISSIONS - Require Local Administrator rights
    Update-Status "Verifying administrative permissions on servers..."
    
    $HasAdminAccess = $false
    $TestedServers = @()
    
    foreach ($Server in ($Servers | Select-Object -First 3)) {
        if (Test-ServerConnection -ServerName $Server.Name -Credential $Script:Credential) {
            $TestedServers += $Server.Name
            
            # Test if user is admin on this server
            $ScriptBlock = {
                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
                $AdminRole = [System.Windows.Principal.WindowsBuiltInRole]::Administrator
                return $UserPrincipal.IsInRole($AdminRole)
            }
            
            $AdminCheck = Invoke-SafeRemoteCommand -ServerName $Server.Name -ScriptBlock $ScriptBlock -Credential $Script:Credential
            if ($AdminCheck.Success -and $AdminCheck.Data) {
                $HasAdminAccess = $true
                break
            }
        }
    }
    
    if (-not $HasAdminAccess) {
        $TestedList = if ($TestedServers.Count -gt 0) { ($TestedServers -join ", ") } else { "None - connection failed" }
        [System.Windows.Forms.MessageBox]::Show(
            "PERMISSION DENIED`n`nThe connected user does not have Local Administrator rights on the servers.`n`nTested Servers: $TestedList`n`nValidation cannot proceed.`n`nREQUIRED: Local Administrator rights on target servers",
            "Insufficient Permissions",
            "OK",
            "Error"
        )
        Update-Status "Utilization validation blocked - not a local administrator"
        return
    }

    # Get ALL servers from inventory
    $Servers = $Script:ServerInventory
    
    if ($Servers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No servers found in inventory", "Info", "OK", "Information")
        return
    }
    
    # Start progress tracking
    if (-not (Start-ValidationProgress -ValidationName "System Utilization" -TotalSteps ($Servers.Count + 2))) {
        return
    }
    
    # Clear previous validation results
    $Script:CurrentResults.Clear()

    Update-ValidationProgress -CurrentStep 1 -StatusText "Preparing system utilization validation..."
    
    if ($Servers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No servers found in inventory", "Info", "OK", "Information")
        return
    }
    
    # Clear existing results
    $Script:CurrentResults.Clear()
    
    # Remove all tabs except Welcome (index 0)
    while ($Global:TabControl.TabPages.Count -gt 1) {
        $Global:TabControl.TabPages.RemoveAt(1)
    }
    
    # Create ONE tab for all servers
    $AllServersTab = New-Object System.Windows.Forms.TabPage
    $AllServersTab.Text = "All Servers Overview"
    $AllServersTab.Padding = New-Object System.Windows.Forms.Padding(10)
    
    # Create scrollable panel
    $ScrollPanel = New-Object System.Windows.Forms.Panel
    $ScrollPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $ScrollPanel.AutoScroll = $true
    $ScrollPanel.BackColor = [System.Drawing.Color]::White
    
    $YPosition = 10
    
    # Loop through each server
    foreach ($Server in $Servers) {
        $ServerName = $Server.Name
        
        if (Test-ServerConnection -ServerName $ServerName -Credential $Script:Credential) {
            $Data = Get-ServerUtilization -ServerName $ServerName -Credential $Script:Credential
            
            if ($Data) {
                # Server Header Panel
                $ServerHeaderPanel = New-Object System.Windows.Forms.Panel
                $ServerHeaderPanel.Location = New-Object System.Drawing.Point(10, $YPosition)
                $ServerHeaderPanel.Size = New-Object System.Drawing.Size(1400, 40)
                $ServerHeaderPanel.BackColor = [System.Drawing.Color]::FromArgb(52, 73, 94)
                
                $ServerLabel = New-Object System.Windows.Forms.Label
                $ServerLabel.Text = "  SERVER: $ServerName"
                $ServerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
                $ServerLabel.ForeColor = [System.Drawing.Color]::White
                $ServerLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
                $ServerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
                $ServerHeaderPanel.Controls.Add($ServerLabel)
                $ScrollPanel.Controls.Add($ServerHeaderPanel)
                
                $YPosition += 50
                
                # CPU Panel
                $CPUPanel = New-Object System.Windows.Forms.GroupBox
                $CPUPanel.Text = "CPU Information"
                $CPUPanel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
                $CPUPanel.Location = New-Object System.Drawing.Point(10, $YPosition)
                $CPUPanel.Size = New-Object System.Drawing.Size(450, 180)
                $CPUPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
                
                $CPUGrid = New-ResultDataGrid -Title "CPU"
                $CPUGrid.Location = New-Object System.Drawing.Point(10, 25)
                $CPUGrid.Size = New-Object System.Drawing.Size(430, 145)
                $CPUGrid.DataSource = [System.Collections.ArrayList]$Data.CPU
                $CPUGrid.Add_DataBindingComplete({
                    foreach ($Row in $CPUGrid.Rows) {
                        $Status = $Row.Cells["Status"].Value
                        if ($Status -eq "Normal") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                        } elseif ($Status -eq "High") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                        }
                    }
                })
                $CPUPanel.Controls.Add($CPUGrid)
                $ScrollPanel.Controls.Add($CPUPanel)
                
                # Memory Panel
                $MemPanel = New-Object System.Windows.Forms.GroupBox
                $MemPanel.Text = "Memory Information"
                $MemPanel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
                $MemPanel.Location = New-Object System.Drawing.Point(470, $YPosition)
                $MemPanel.Size = New-Object System.Drawing.Size(450, 180)
                $MemPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
                
                $MemGrid = New-ResultDataGrid -Title "Memory"
                $MemGrid.Location = New-Object System.Drawing.Point(10, 25)
                $MemGrid.Size = New-Object System.Drawing.Size(430, 145)
                $MemGrid.DataSource = [System.Collections.ArrayList]$Data.Memory
                $MemGrid.Add_DataBindingComplete({
                    foreach ($Row in $MemGrid.Rows) {
                        $Status = $Row.Cells["Status"].Value
                        if ($Status -eq "Normal") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                        } elseif ($Status -eq "High") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                        }
                    }
                })
                $MemPanel.Controls.Add($MemGrid)
                $ScrollPanel.Controls.Add($MemPanel)
                
                # Status Indicator Panel
                $StatusPanel = New-Object System.Windows.Forms.Panel
                $StatusPanel.Location = New-Object System.Drawing.Point(930, $YPosition)
                $StatusPanel.Size = New-Object System.Drawing.Size(480, 180)
                $StatusPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
                $StatusPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 250)
                
                $CPUUsageValue = ($Data.CPU | Where-Object { $_.Metric -eq "Current Usage" }).Value
                $CPUUsageNum = [double]($CPUUsageValue -replace '%', '')
                
                $CPUStatusLabel = New-Object System.Windows.Forms.Label
                $CPUStatusLabel.Text = "CPU Usage"
                $CPUStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
                $CPUStatusLabel.Location = New-Object System.Drawing.Point(10, 15)
                $CPUStatusLabel.Size = New-Object System.Drawing.Size(200, 25)
                $StatusPanel.Controls.Add($CPUStatusLabel)
                
                $CPUProgressBar = New-Object System.Windows.Forms.ProgressBar
                $CPUProgressBar.Location = New-Object System.Drawing.Point(10, 45)
                $CPUProgressBar.Size = New-Object System.Drawing.Size(460, 30)
                $CPUProgressBar.Minimum = 0
                $CPUProgressBar.Maximum = 100
                $CPUProgressBar.Value = [math]::Min(100, [int]$CPUUsageNum)
                $StatusPanel.Controls.Add($CPUProgressBar)
                
                $CPUValueLabel = New-Object System.Windows.Forms.Label
                $CPUValueLabel.Text = "$CPUUsageNum%"
                $CPUValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
                $CPUValueLabel.Location = New-Object System.Drawing.Point(220, 12)
                $CPUValueLabel.Size = New-Object System.Drawing.Size(100, 25)
                $CPUValueLabel.ForeColor = if ($CPUUsageNum -lt 80) { [System.Drawing.Color]::FromArgb(39, 174, 96) } else { [System.Drawing.Color]::FromArgb(231, 76, 60) }
                $StatusPanel.Controls.Add($CPUValueLabel)
                
                $MemUsageValue = ($Data.Memory | Where-Object { $_.Metric -eq "Usage Percentage" }).Value
                $MemUsageNum = [double]($MemUsageValue -replace '%', '')
                
                $MemStatusLabel = New-Object System.Windows.Forms.Label
                $MemStatusLabel.Text = "Memory Usage"
                $MemStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
                $MemStatusLabel.Location = New-Object System.Drawing.Point(10, 90)
                $MemStatusLabel.Size = New-Object System.Drawing.Size(200, 25)
                $StatusPanel.Controls.Add($MemStatusLabel)
                
                $MemProgressBar = New-Object System.Windows.Forms.ProgressBar
                $MemProgressBar.Location = New-Object System.Drawing.Point(10, 120)
                $MemProgressBar.Size = New-Object System.Drawing.Size(460, 30)
                $MemProgressBar.Minimum = 0
                $MemProgressBar.Maximum = 100
                $MemProgressBar.Value = [math]::Min(100, [int]$MemUsageNum)
                $StatusPanel.Controls.Add($MemProgressBar)
                
                $MemValueLabel = New-Object System.Windows.Forms.Label
                $MemValueLabel.Text = "$MemUsageNum%"
                $MemValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
                $MemValueLabel.Location = New-Object System.Drawing.Point(220, 87)
                $MemValueLabel.Size = New-Object System.Drawing.Size(100, 25)
                $MemValueLabel.ForeColor = if ($MemUsageNum -lt 85) { [System.Drawing.Color]::FromArgb(39, 174, 96) } else { [System.Drawing.Color]::FromArgb(231, 76, 60) }
                $StatusPanel.Controls.Add($MemValueLabel)
                
                $ScrollPanel.Controls.Add($StatusPanel)
                $YPosition += 190
                
                # Disk Panel
                $DiskPanel = New-Object System.Windows.Forms.GroupBox
                $DiskPanel.Text = "Disk Information"
                $DiskPanel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
                $DiskPanel.Location = New-Object System.Drawing.Point(10, $YPosition)
                $DiskPanel.Size = New-Object System.Drawing.Size(1400, 200)
                $DiskPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
                
                $DiskGrid = New-ResultDataGrid -Title "Disks"
                $DiskGrid.Location = New-Object System.Drawing.Point(10, 25)
                $DiskGrid.Size = New-Object System.Drawing.Size(1380, 165)
                $DiskGrid.DataSource = [System.Collections.ArrayList]$Data.Disks
                $DiskGrid.Add_DataBindingComplete({
                    foreach ($Row in $DiskGrid.Rows) {
                        $Status = $Row.Cells["Status"].Value
                        if ($Status -eq "Normal") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                        } elseif ($Status -eq "Warning") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                        } elseif ($Status -eq "Critical") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Error
                        }
                    }
                })
                $DiskPanel.Controls.Add($DiskGrid)
                $ScrollPanel.Controls.Add($DiskPanel)
                $YPosition += 220
                
                # Separator
                $Separator = New-Object System.Windows.Forms.Panel
                $Separator.Location = New-Object System.Drawing.Point(10, $YPosition)
                $Separator.Size = New-Object System.Drawing.Size(1400, 2)
                $Separator.BackColor = [System.Drawing.Color]::FromArgb(189, 195, 199)
                $ScrollPanel.Controls.Add($Separator)
                $YPosition += 20
                
                # Save results for export
                $Script:CurrentResults[$ServerName] = @{
                    Type = "Utilization"
                    Results = @{
                        CPU = $Data.CPU
                        Memory = $Data.Memory
                        Disks = $Data.Disks
                    }
                    Timestamp = Get-Date
                }
            }
        }
    }
    
    # Add the scroll panel to the tab
    $AllServersTab.Controls.Add($ScrollPanel)
    
    # Add the tab to the main control
    $Global:TabControl.TabPages.Add($AllServersTab)
    
    Complete-ValidationProgress -CompletionMessage "Utilization check completed"
    [System.Windows.Forms.MessageBox]::Show("System utilization data loaded for all servers.", "Complete", "OK", "Information")
}

function Show-ExchangeResults {
    # Check if user is connected first
    if (-not $Script:Credential) {
        [System.Windows.Forms.MessageBox]::Show(
            "You must connect with credentials first!`n`nClick the 'Connect' button to authenticate before running validations.",
            "Authentication Required",
            "OK",
            "Warning"
        )
        return
    }
    
    # CHECK PERMISSIONS FIRST - MANDATORY
    Update-Status "Checking Exchange permissions..."
    $PermCheck = Test-ExchangePermissions -Credential $Script:Credential
    
    # Block execution if no permissions
    if (-not $PermCheck.HasPermission) {
        $ErrorDetails = "Missing Permissions:`n"
        foreach ($Missing in $PermCheck.MissingPermissions) {
            $ErrorDetails += "- $Missing`n"
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "PERMISSION DENIED`n`nYou do not have the required permissions to run Exchange validation.`n`n$ErrorDetails`nValidation cannot proceed.",
            "Insufficient Permissions",
            "OK",
            "Error"
        )
        Update-Status "Exchange validation blocked - insufficient permissions"
        return
    }
    
    # Show what permissions were verified
    $ContinueValidation = Show-PermissionCheckDialog -ValidationType "Exchange Server" -PermissionResults $PermCheck
    
    if (-not $ContinueValidation) {
        Update-Status "Exchange validation cancelled by user"
        return
    }
    
    $Servers = $Script:ServerInventory | Where-Object { $_.Role -match "Exchange" }
    
    if ($Servers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No Exchange servers found", "Info", "OK", "Information")
        return
    }
    
    # Start progress tracking
    if (-not (Start-ValidationProgress -ValidationName "Exchange Validation" -TotalSteps ($Servers.Count + 2))) {
        return
    }

    # Clear previous validation results
    $Script:CurrentResults.Clear()

    Update-ValidationProgress -CurrentStep 1 -StatusText "Preparing Exchange validation..."
    if ($Servers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No Exchange servers found", "Info", "OK", "Information")
        return
    }
    while ($Global:TabControl.TabPages.Count -gt 1) {
        $Global:TabControl.TabPages.RemoveAt(1)
    }
    $StepCounter = 2
    foreach ($Server in $Servers) {
        $ServerName = $Server.Name
        
        Update-ValidationProgress -CurrentStep $StepCounter -StatusText "Validating $ServerName..."
        $StepCounter++
        
        if (Test-ServerConnection -ServerName $ServerName -Credential $Script:Credential) {
            Update-Status "Validating Exchange on $ServerName..."
            $Data = Test-ExchangeComprehensive -ServerName $ServerName -Credential $Script:Credential
            if ($Data) {
                $TabPage = New-Object System.Windows.Forms.TabPage
                $TabPage.Text = $ServerName
                $TabPage.Padding = New-Object System.Windows.Forms.Padding(3)
                $SubTabControl = New-Object System.Windows.Forms.TabControl
                $SubTabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
                if ($Data.ServerInfo.Count -gt 0) {
                    $SvrTab = New-Object System.Windows.Forms.TabPage
                    $SvrTab.Text = "Server Info"
                    $SvrGrid = New-ResultDataGrid -Title "ServerInfo"
                    $SvrGrid.DataSource = [System.Collections.ArrayList]$Data.ServerInfo
                    $SvrTab.Controls.Add($SvrGrid)
                    $SubTabControl.TabPages.Add($SvrTab)
                }
                if ($Data.DiskInfo.Count -gt 0) {
                    $DiskTab = New-Object System.Windows.Forms.TabPage
                    $DiskTab.Text = "Disk Details"
                    $DiskGrid = New-ResultDataGrid -Title "Disks"
                    $DiskGrid.DataSource = [System.Collections.ArrayList]$Data.DiskInfo
                    $DiskGrid.Add_DataBindingComplete({
                        foreach ($Row in $DiskGrid.Rows) {
                            $Status = $Row.Cells["Status"].Value
                            if ($Status -eq "Normal") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                            elseif ($Status -eq "Warning") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning }
                            elseif ($Status -eq "Critical") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Error }
                        }
                    })
                    $DiskTab.Controls.Add($DiskGrid)
                    $SubTabControl.TabPages.Add($DiskTab)
                }
                if ($Data.NetworkAdapters.Count -gt 0) {
                    $NetAdapTab = New-Object System.Windows.Forms.TabPage
                    $NetAdapTab.Text = "Network Adapters"
                    $NetAdapGrid = New-ResultDataGrid -Title "Network"
                    $NetAdapGrid.DataSource = [System.Collections.ArrayList]$Data.NetworkAdapters
                    $NetAdapTab.Controls.Add($NetAdapGrid)
                    $SubTabControl.TabPages.Add($NetAdapTab)
                }
                if ($Data.WindowsServices.Count -gt 0) {
                    $SvcTab = New-Object System.Windows.Forms.TabPage
                    $SvcTab.Text = "Windows Services"
                    $SvcGrid = New-ResultDataGrid -Title "Services"
                    $SvcGrid.DataSource = [System.Collections.ArrayList]$Data.WindowsServices
                    $SvcGrid.Add_DataBindingComplete({
                        foreach ($Row in $SvcGrid.Rows) {
                            if ($Row.Cells["State"].Value -eq "OK") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                            else { $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning }
                        }
                    })
                    $SvcTab.Controls.Add($SvcGrid)
                    $SubTabControl.TabPages.Add($SvcTab)
                }
                if ($Data.General.Count -gt 0) {
                    $GenTab = New-Object System.Windows.Forms.TabPage
                    $GenTab.Text = "General"
                    $GenGrid = New-ResultDataGrid -Title "General"
                    $GenGrid.DataSource = [System.Collections.ArrayList]$Data.General
                    $GenTab.Controls.Add($GenGrid)
                    $SubTabControl.TabPages.Add($GenTab)
                }
                if ($Data.AcceptedDomains.Count -gt 0) {
                    $DomTab = New-Object System.Windows.Forms.TabPage
                    $DomTab.Text = "Accepted Domains"
                    $DomGrid = New-ResultDataGrid -Title "Domains"
                    $DomGrid.DataSource = [System.Collections.ArrayList]$Data.AcceptedDomains
                    $DomGrid.Add_DataBindingComplete({
                        foreach ($Row in $DomGrid.Rows) {
                            if ($Row.Cells["Status"].Value -eq "OK") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                        }
                    })
                    $DomTab.Controls.Add($DomGrid)
                    $SubTabControl.TabPages.Add($DomTab)
                }
                if ($Data.MailboxDatabases.Count -gt 0) {
                    $DBTab = New-Object System.Windows.Forms.TabPage
                    $DBTab.Text = "Mailbox Databases"
                    $DBGrid = New-ResultDataGrid -Title "Databases"
                    $DBGrid.DataSource = [System.Collections.ArrayList]$Data.MailboxDatabases
                    $DBGrid.Add_DataBindingComplete({
                        foreach ($Row in $DBGrid.Rows) {
                            if ($Row.Cells["Status"].Value -eq "OK") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                            elseif ($Row.Cells["Status"].Value -eq "ERROR") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Error }
                        }
                    })
                    $DBTab.Controls.Add($DBGrid)
                    $SubTabControl.TabPages.Add($DBTab)
                }
                if ($Data.SystemMailboxes.Count -gt 0) {
                    $SysTab = New-Object System.Windows.Forms.TabPage
                    $SysTab.Text = "System Mailboxes"
                    $SysGrid = New-ResultDataGrid -Title "SystemMbx"
                    $SysGrid.DataSource = [System.Collections.ArrayList]$Data.SystemMailboxes
                    $SysTab.Controls.Add($SysGrid)
                    $SubTabControl.TabPages.Add($SysTab)
                }
                if ($Data.VirtualDirectories.Count -gt 0) {
                    $VDirTab = New-Object System.Windows.Forms.TabPage
                    $VDirTab.Text = "Virtual Directories"
                    $VDirGrid = New-ResultDataGrid -Title "VDirs"
                    $VDirGrid.DataSource = [System.Collections.ArrayList]$Data.VirtualDirectories
                    $VDirGrid.Add_DataBindingComplete({
                        foreach ($Row in $VDirGrid.Rows) {
                            if ($Row.Cells["Status"].Value -eq "OK") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                            else { $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning }
                        }
                    })
                    $VDirTab.Controls.Add($VDirGrid)
                    $SubTabControl.TabPages.Add($VDirTab)
                }
                if ($Data.Certificates.Count -gt 0) {
                    $CertTab = New-Object System.Windows.Forms.TabPage
                    $CertTab.Text = "SSL Certificates"
                    $CertGrid = New-ResultDataGrid -Title "Certs"
                    $CertGrid.DataSource = [System.Collections.ArrayList]$Data.Certificates
                    $CertGrid.Add_DataBindingComplete({
                        foreach ($Row in $CertGrid.Rows) {
                            if ($Row.Cells["Status"].Value -eq "Valid") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                            elseif ($Row.Cells["Status"].Value -eq "Expiring Soon") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning }
                            else { $Row.DefaultCellStyle.BackColor = $Script:Colors.Error }
                        }
                    })
                    $CertTab.Controls.Add($CertGrid)
                    $SubTabControl.TabPages.Add($CertTab)
                }
                if ($Data.SendConnectors.Count -gt 0) {
                    $ConnTab = New-Object System.Windows.Forms.TabPage
                    $ConnTab.Text = "Send Connectors"
                    $ConnGrid = New-ResultDataGrid -Title "Connectors"
                    $ConnGrid.DataSource = [System.Collections.ArrayList]$Data.SendConnectors
                    $ConnGrid.Add_DataBindingComplete({
                        foreach ($Row in $ConnGrid.Rows) {
                            if ($Row.Cells["Status"].Value -eq "OK") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                        }
                    })
                    $ConnTab.Controls.Add($ConnGrid)
                    $SubTabControl.TabPages.Add($ConnTab)
                }
                if ($Data.DAG.Count -gt 0) {
                    $DAGTab = New-Object System.Windows.Forms.TabPage
                    $DAGTab.Text = "DAG"
                    $DAGGrid = New-ResultDataGrid -Title "DAG"
                    $DAGGrid.DataSource = [System.Collections.ArrayList]$Data.DAG
                    $DAGTab.Controls.Add($DAGGrid)
                    $SubTabControl.TabPages.Add($DAGTab)
                }
                if ($Data.InternetAccess.Count -gt 0) {
                    $NetTab = New-Object System.Windows.Forms.TabPage
                    $NetTab.Text = "Internet Access"
                    $NetGrid = New-ResultDataGrid -Title "Network"
                    $NetGrid.DataSource = [System.Collections.ArrayList]$Data.InternetAccess
                    $NetGrid.Add_DataBindingComplete({
                        foreach ($Row in $NetGrid.Rows) {
                            if ($Row.Cells["Status"].Value -eq "OK") { $Row.DefaultCellStyle.BackColor = $Script:Colors.Success }
                            else { $Row.DefaultCellStyle.BackColor = $Script:Colors.Error }
                        }
                    })
                    $NetTab.Controls.Add($NetGrid)
                    $SubTabControl.TabPages.Add($NetTab)
                }
                $TabPage.Controls.Add($SubTabControl)
                $Global:TabControl.TabPages.Add($TabPage)
                $Script:CurrentResults[$ServerName] = @{
                    Type = "Exchange"
                    Results = $Data
                    Timestamp = Get-Date
                }
            }
        }
    }
    Complete-ValidationProgress -CompletionMessage "Exchange validation completed"
    [System.Windows.Forms.MessageBox]::Show("Exchange validation complete.", "Complete", "OK", "Information")
}

function Show-ADResults {
    # Check if user is connected first
    if (-not $Script:Credential) {
        [System.Windows.Forms.MessageBox]::Show(
            "You must connect with credentials first!`n`nClick the 'Connect' button to authenticate before running validations.",
            "Authentication Required",
            "OK",
            "Warning"
        )
        return
    }
    
    # CHECK PERMISSIONS FIRST - MANDATORY
    Update-Status "Checking Active Directory permissions..."
    $PermCheck = Test-ADPermissions -Credential $Script:Credential
    
    # Block execution if no permissions
    if (-not $PermCheck.HasPermission) {
        $ErrorDetails = "Missing Permissions:`n"
        foreach ($Missing in $PermCheck.MissingPermissions) {
            $ErrorDetails += "- $Missing`n"
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "PERMISSION DENIED`n`nYou do not have the required permissions to run AD validation.`n`n$ErrorDetails`nValidation cannot proceed.",
            "Insufficient Permissions",
            "OK",
            "Error"
        )
        Update-Status "AD validation blocked - insufficient permissions"
        return
    }
    
    # Show what permissions were verified
    $ContinueValidation = Show-PermissionCheckDialog -ValidationType "Active Directory" -PermissionResults $PermCheck
    
    if (-not $ContinueValidation) {
        Update-Status "AD validation cancelled by user"
        return
    }
    
    # Get Domain Controllers from inventory
    
    # Get Domain Controllers from inventory
    $DCs = $Script:ServerInventory | Where-Object { $_.Role -match "DC|Domain Controller|AD" }
    
    if ($DCs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No Domain Controllers found in inventory.`n`nAdd servers with role 'DC' to servers.txt", "Info", "OK", "Information")
        return
    }
    
    # Start progress tracking
    if (-not (Start-ValidationProgress -ValidationName "Active Directory Validation" -TotalSteps ($DCs.Count + 2))) {
        return
    }

    # Clear previous validation results
    $Script:CurrentResults.Clear()

    Update-ValidationProgress -CurrentStep 1 -StatusText "Preparing AD validation..."
    
    # Clear existing tabs except Welcome
    while ($Global:TabControl.TabPages.Count -gt 1) {
        $Global:TabControl.TabPages.RemoveAt(1)
    }
    
    $StepCounter = 2
    foreach ($DC in $DCs) {
        $ServerName = $DC.Name
        
        Update-ValidationProgress -CurrentStep $StepCounter -StatusText "Validating AD on $ServerName..."
        $StepCounter++
        
        if (Test-ServerConnection -ServerName $ServerName -Credential $Script:Credential) {
            $Data = Test-ActiveDirectoryComprehensive -ServerName $ServerName -Credential $Script:Credential
            
            if ($Data -and -not $Data.Error) {
                # Create main tab for this DC
                $TabPage = New-Object System.Windows.Forms.TabPage
                $TabPage.Text = $ServerName
                $TabPage.Padding = New-Object System.Windows.Forms.Padding(3)
                
                # Create sub-tab control
                $SubTabControl = New-Object System.Windows.Forms.TabControl
                $SubTabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
                
                # Add tabs for each category
                $Categories = @(
                    @{Name="Replication"; Key="Replication"; ColorCode=$true},
                    @{Name="GPOs"; Key="GPOs"; ColorCode=$true},
                    @{Name="Service Accounts"; Key="ServiceAccounts"; ColorCode=$true},
                    @{Name="Admin Accounts"; Key="AdminAccounts"; ColorCode=$true},
                    @{Name="OU Structure"; Key="OUStructure"; ColorCode=$true},
                    @{Name="Account Descriptions"; Key="AccountDescriptions"; ColorCode=$true},
                    @{Name="Groups"; Key="Groups"; ColorCode=$true},
                    @{Name="AD Features"; Key="ADFeatures"; ColorCode=$true},
                    @{Name="NTP Policy"; Key="NTPPolicy"; ColorCode=$true},
                    @{Name="Security Logs"; Key="SecurityLogs"; ColorCode=$true},
                    @{Name="Sites & Subnets"; Key="SitesAndSubnets"; ColorCode=$true},
                    @{Name="DNS Forwarders"; Key="DNSForwarders"; ColorCode=$true},
                    @{Name="Auto Updates"; Key="AutomaticUpdates"; ColorCode=$false},
                    @{Name="Subnets in Sites"; Key="SubnetsInSites"; ColorCode=$true},
                    @{Name="Internet Access"; Key="InternetAccess"; ColorCode=$true}
                )
                
                foreach ($Category in $Categories) {
                    if ($Data[$Category.Key].Count -gt 0) {
                        $Tab = New-Object System.Windows.Forms.TabPage
                        $Tab.Text = $Category.Name
                        
                        $Grid = New-ResultDataGrid -Title $Category.Name
                        $Grid.DataSource = [System.Collections.ArrayList]$Data[$Category.Key]
                        
                        if ($Category.ColorCode) {
                            $Grid.Add_DataBindingComplete({
                                foreach ($Row in $Grid.Rows) {
                                    $StatusCell = $Row.Cells | Where-Object { $_.OwningColumn.Name -eq "Status" -or $_.OwningColumn.Name -eq "Result" }
                                    if ($StatusCell) {
                                        $StatusValue = $StatusCell.Value
                                        if ($StatusValue -match "OK|Enabled|Running|Normal|Compliant") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                                        }
                                        elseif ($StatusValue -match "Warning|Check|Missing Description|Too Small") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                                        }
                                        elseif ($StatusValue -match "Error|Failed|Critical|Missing|SECURITY|RISK|Disabled") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Error
                                        }
                                        elseif ($StatusValue -match "Info") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Info
                                        }
                                    }
                                }
                            })
                        }
                        
                        $Tab.Controls.Add($Grid)
                        $SubTabControl.TabPages.Add($Tab)
                    }
                }
                
                $TabPage.Controls.Add($SubTabControl)
                $Global:TabControl.TabPages.Add($TabPage)
                
                # Save results for export
                $Script:CurrentResults[$ServerName] = @{
                    Type = "ActiveDirectory"
                    Results = $Data
                    Timestamp = Get-Date
                }
            }
            elseif ($Data.Error) {
                [System.Windows.Forms.MessageBox]::Show("Error on $ServerName`:`n$($Data.Error)", "AD Validation Error", "OK", "Error")
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show("Cannot connect to $ServerName", "Connection Failed", "OK", "Warning")
        }
    }
    
    Complete-ValidationProgress -CompletionMessage "Active Directory validation completed"
    [System.Windows.Forms.MessageBox]::Show("Active Directory validation complete.", "Complete", "OK", "Information")
}

function Show-ADFSResults {
    # Check if user is connected first
    if (-not $Script:Credential) {
        [System.Windows.Forms.MessageBox]::Show(
            "You must connect with credentials first!`n`nClick the 'Connect' button to authenticate before running validations.",
            "Authentication Required",
            "OK",
            "Warning"
        )
        return
    }
    
    # CHECK PERMISSIONS FIRST - MANDATORY
    Update-Status "Checking ADFS permissions..."
    $PermCheck = Test-ADFSPermissions -Credential $Script:Credential
    
    # Block execution if no permissions
    if (-not $PermCheck.HasPermission) {
        $ErrorDetails = "Missing Permissions:`n"
        foreach ($Missing in $PermCheck.MissingPermissions) {
            $ErrorDetails += "- $Missing`n"
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "PERMISSION DENIED`n`nYou do not have the required permissions to run ADFS validation.`n`n$ErrorDetails`nValidation cannot proceed.",
            "Insufficient Permissions",
            "OK",
            "Error"
        )
        Update-Status "ADFS validation blocked - insufficient permissions"
        return
    }
    
    # Show what permissions were verified
    $ContinueValidation = Show-PermissionCheckDialog -ValidationType "ADFS" -PermissionResults $PermCheck
    
    if (-not $ContinueValidation) {
        Update-Status "ADFS validation cancelled by user"
        return
    }
    
    # Get ADFS servers from inventory
    
    # Get ADFS servers from inventory
    $ADFSServers = $Script:ServerInventory | Where-Object { $_.Role -match "ADFS|Federation" }
    
    if ($ADFSServers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No ADFS servers found in inventory.`n`nAdd servers with role 'ADFS' to servers.txt", "Info", "OK", "Information")
        return
    }
    
    # Start progress tracking
    if (-not (Start-ValidationProgress -ValidationName "ADFS Validation" -TotalSteps ($ADFSServers.Count + 2))) {
        return
    }
    
    # Clear previous validation results
    $Script:CurrentResults.Clear()

    Update-ValidationProgress -CurrentStep 1 -StatusText "Preparing ADFS validation..."
    
    # Clear existing tabs except Welcome
    while ($Global:TabControl.TabPages.Count -gt 1) {
        $Global:TabControl.TabPages.RemoveAt(1)
    }
    
    $StepCounter = 2
    foreach ($Server in $ADFSServers) {
        $ServerName = $Server.Name
        
        Update-ValidationProgress -CurrentStep $StepCounter -StatusText "Validating ADFS on $ServerName..."
        $StepCounter++
        
        if (Test-ServerConnection -ServerName $ServerName -Credential $Script:Credential) {
            $Data = Test-ADFSComprehensive -ServerName $ServerName -Credential $Script:Credential
            
            if ($Data) {
                # Create main tab for this ADFS server
                $TabPage = New-Object System.Windows.Forms.TabPage
                $TabPage.Text = $ServerName
                $TabPage.Padding = New-Object System.Windows.Forms.Padding(3)
                
                # Create sub-tab control
                $SubTabControl = New-Object System.Windows.Forms.TabControl
                $SubTabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
                
                # Add tabs for each category
                $Categories = @(
                    @{Name="Service Status"; Key="ServiceStatus"; ColorCode=$true},
                    @{Name="Communication Ports"; Key="CommunicationPorts"; ColorCode=$true},
                    @{Name="SSL Certificates"; Key="SSLCertificates"; ColorCode=$true},
                    @{Name="Token Signing Certs"; Key="TokenSigningCerts"; ColorCode=$true},
                    @{Name="Service Account"; Key="ServiceAccount"; ColorCode=$true},
                    @{Name="MFA Configuration"; Key="MFAConfiguration"; ColorCode=$true},
                    @{Name="ADFS Properties"; Key="ADFSProperties"; ColorCode=$false},
                    @{Name="Farm Information"; Key="FarmInformation"; ColorCode=$false}
                )
                
                foreach ($Category in $Categories) {
                    if ($Data[$Category.Key].Count -gt 0) {
                        $Tab = New-Object System.Windows.Forms.TabPage
                        $Tab.Text = $Category.Name
                        
                        $Grid = New-ResultDataGrid -Title $Category.Name
                        $Grid.DataSource = [System.Collections.ArrayList]$Data[$Category.Key]
                        
                        if ($Category.ColorCode) {
                            $Grid.Add_DataBindingComplete({
                                foreach ($Row in $Grid.Rows) {
                                    # Find status column (might be named Status, StatusCode, or Result)
                                    $StatusCell = $Row.Cells | Where-Object { 
                                        $_.OwningColumn.Name -eq "Status" -or 
                                        $_.OwningColumn.Name -eq "StatusCode" -or 
                                        $_.OwningColumn.Name -eq "Result"
                                    }
                                    
                                    if ($StatusCell) {
                                        $StatusValue = $StatusCell.Value
                                        if ($StatusValue -match "OK|Running|Success|Valid|Listening|Enabled|Active|Configured|Best Practice") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                                        }
                                        elseif ($StatusValue -match "Warning|Check|Expiring Soon|Info|Not Configured|Default|Check Manually|Found") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                                        }
                                        elseif ($StatusValue -match "Error|Failed|Critical|EXPIRED|Not Running|Not Listening|Missing|Not Found|No MFA") {
                                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Error
                                        }
                                    }
                                }
                            })
                        }
                        
                        $Tab.Controls.Add($Grid)
                        $SubTabControl.TabPages.Add($Tab)
                    }
                }
                
                $TabPage.Controls.Add($SubTabControl)
                $Global:TabControl.TabPages.Add($TabPage)
                
                # Save results for export
                $Script:CurrentResults[$ServerName] = @{
                    Type = "ADFS"
                    Results = $Data
                    Timestamp = Get-Date
                }
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("No data returned from $ServerName", "ADFS Validation Error", "OK", "Warning")
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show("Cannot connect to $ServerName", "Connection Failed", "OK", "Warning")
        }
    }
    
    Complete-ValidationProgress -CompletionMessage "ADFS validation completed"
    [System.Windows.Forms.MessageBox]::Show("ADFS validation complete.", "Complete", "OK", "Information")
}

#endregion

#region Export Functions

function Export-ValidationReport {
    if ($Script:CurrentResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No validation results to export", "Export Report", "OK", "Warning")
        return
    }
    try {
        $OutputPath = ".\Reports"
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        $ReportFileName = "Exchange-Validation-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        $ReportPath = Join-Path $OutputPath $ReportFileName
        $HTMLContent = Generate-HTMLReport -Results $Script:CurrentResults
        $HTMLContent | Out-File -FilePath $ReportPath -Encoding UTF8
        Update-Status "Report exported successfully"
        $Result = [System.Windows.Forms.MessageBox]::Show(
            "Report exported to: $ReportPath`n`nOpen now?",
            "Export Complete",
            "YesNo",
            "Information"
        )
        if ($Result -eq "Yes") {
            Start-Process $ReportPath
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error exporting: $($_.Exception.Message)", "Export Error", "OK", "Error")
    }
}

function Generate-HTMLReport {
    param([hashtable]$Results)
    $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Exchange Infrastructure Validation Report</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { max-width: 1600px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        h1 { color: #2c3e50; border-bottom: 4px solid #3498db; padding-bottom: 15px; font-size: 2.5em; margin-bottom: 30px; }
        h2 { color: #34495e; margin-top: 40px; background: linear-gradient(135deg, #f8f9fa, #e9ecef); padding: 15px; border-left: 5px solid #3498db; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        th { background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 14px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 0.9em; }
        td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background: #f8f9fa; }
        tr:last-child td { border-bottom: none; }
        .success { background: #d4edda; color: #155724; font-weight: 600; }
        .warning { background: #fff3cd; color: #856404; font-weight: 600; }
        .error { background: #f8d7da; color: #721c24; font-weight: 600; }
        .section { margin: 30px 0; padding: 25px; background: #f8f9fa; border-radius: 8px; border-left: 5px solid #3498db; }
        .timestamp { color: #7f8c8d; font-size: 0.95em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Infrastructure Handover Report</h1>
        <p class="timestamp"><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@
    foreach ($ServerName in $Results.Keys | Sort-Object) {
        $ServerData = $Results[$ServerName]
        $Data = $ServerData.Results
        $HTML += "<h2>Server: $ServerName</h2>"
        foreach ($Category in $Data.Keys | Sort-Object) {
            if ($Data[$Category].Count -gt 0) {
                $HTML += "<div class='section'><h3>$Category</h3><table><tr>"
                $FirstItem = $Data[$Category][0]
                $Properties = $FirstItem.PSObject.Properties.Name
                foreach ($Prop in $Properties) {
                    $HTML += "<th>$Prop</th>"
                }
                $HTML += "</tr>"
                foreach ($Item in $Data[$Category]) {
                    $RowClass = ""
                    if ($Item.Status -eq "OK" -or $Item.Status -eq "Normal" -or $Item.Status -eq "Valid") {
                        $RowClass = "success"
                    }
                    elseif ($Item.Status -match "Warning|Check|Expiring|Info") {
                        $RowClass = "warning"
                    }
                    elseif ($Item.Status -match "Error|Failed|EXPIRED|SECURITY|Critical") {
                        $RowClass = "error"
                    }
                    $HTML += "<tr class='$RowClass'>"
                    foreach ($Prop in $Properties) {
                        $HTML += "<td>$($Item.$Prop)</td>"
                    }
                    $HTML += "</tr>"
                }
                $HTML += "</table></div>"
            }
        }
    }
    $HTML += "</div></body></html>"
    return $HTML
}

#endregion

#region Server Inventory

function Load-ServerInventory {
    $ServersFile = ".\servers.txt"
    if (-not (Test-Path $ServersFile)) {
        $SampleContent = @"
# Exchange Servers
NN-TEST-EX01.nourtest.com, Exchange
NN-TEST-EX02.nourtest.com, Exchange
"@
        $SampleContent | Out-File -FilePath $ServersFile -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Sample servers.txt created.", "Server Inventory", "OK", "Information")
        return @()
    }
    $Servers = @()
    $Content = Get-Content $ServersFile
    foreach ($Line in $Content) {
        if ($Line.Trim() -and -not $Line.StartsWith('#')) {
            $Parts = $Line.Split(',')
            if ($Parts.Count -ge 2) {
                $Servers += @{
                    Name = $Parts[0].Trim()
                    Role = $Parts[1].Trim()
                }
            }
        }
    }
    return $Servers
}

#endregion

#region GUI

function Show-ValidationGUI {
    $Script:ServerInventory = Load-ServerInventory
    $Global:MainForm = New-Object System.Windows.Forms.Form
    $Global:MainForm.Text = "Infrastructure Validation Tool v2.4"
    $Global:MainForm.Size = New-Object System.Drawing.Size(1500, 900)
    $Global:MainForm.StartPosition = "CenterScreen"
    $Global:MainForm.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $Global:MainForm.MinimumSize = New-Object System.Drawing.Size(1200, 700)
    $Global:MainForm.MaximizeBox = $true
    $Global:MainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Infrastructure Handover Validation Tool"
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.ForeColor = $Script:Colors.Header
    $TitleLabel.AutoSize = $true
    $TitleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $Global:MainForm.Controls.Add($TitleLabel)
    $SubtitleLabel = New-Object System.Windows.Forms.Label
    $SubtitleLabel.Text = "Excel-Style Table Display with Comprehensive Exchange Validation"
    $SubtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $SubtitleLabel.ForeColor = $Script:Colors.GridHeader
    $SubtitleLabel.AutoSize = $true
    $SubtitleLabel.Location = New-Object System.Drawing.Point(20, 60)
    $Global:MainForm.Controls.Add($SubtitleLabel)
    $ButtonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $ButtonPanel.Size = New-Object System.Drawing.Size(1460, 70)
    $ButtonPanel.Location = New-Object System.Drawing.Point(20, 90)
    $ButtonPanel.BackColor = [System.Drawing.Color]::White
    $ButtonPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $ButtonPanel.Padding = New-Object System.Windows.Forms.Padding(10)
    $ButtonPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $Global:MainForm.Controls.Add($ButtonPanel)

    function New-StyledButton {
        param([string]$Text, [System.Drawing.Color]$BackColor, [scriptblock]$ClickAction)
        $Button = New-Object System.Windows.Forms.Button
        $Button.Text = $Text
        $Button.Size = New-Object System.Drawing.Size(220, 45)
        $Button.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $Button.BackColor = $BackColor
        $Button.ForeColor = [System.Drawing.Color]::White
        $Button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $Button.FlatAppearance.BorderSize = 0
        $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
        $Button.Margin = New-Object System.Windows.Forms.Padding(5)
        $Button.Add_Click($ClickAction)
        return $Button
    }
    
    # Create Connect/Disconnect button FIRST
    $Global:ConnectButton = New-StyledButton -Text "Connect" -BackColor ([System.Drawing.Color]::FromArgb(39, 174, 96)) -ClickAction {
        if ($Script:Credential) {
            Disconnect-Credentials
        }
        else {
            Connect-WithCredentials
        }
    }
    $ButtonPanel.Controls.Add($Global:ConnectButton)
    $UtilButton = New-StyledButton -Text "System Utilization" -BackColor ([System.Drawing.Color]::FromArgb(52, 152, 219)) -ClickAction { Show-UtilizationResults }
    $ButtonPanel.Controls.Add($UtilButton)
    $ExchangeButton = New-StyledButton -Text "Exchange Validation" -BackColor ([System.Drawing.Color]::FromArgb(155, 89, 182)) -ClickAction { Show-ExchangeResults }
    $ButtonPanel.Controls.Add($ExchangeButton)
    # NEW AD VALIDATION BUTTON
    $ADButton = New-StyledButton -Text "AD Validation" -BackColor ([System.Drawing.Color]::FromArgb(46, 204, 113)) -ClickAction { Show-ADResults }
    $ButtonPanel.Controls.Add($ADButton)
    # NEW ADFS VALIDATION BUTTON
    $ADFSButton = New-StyledButton -Text "ADFS Validation" -BackColor ([System.Drawing.Color]::FromArgb(230, 126, 34)) -ClickAction { Show-ADFSResults }
    $ButtonPanel.Controls.Add($ADFSButton)
    $ExportButton = New-StyledButton -Text "Export Report" -BackColor ([System.Drawing.Color]::FromArgb(44, 62, 80)) -ClickAction { Export-ValidationReport }
    $ButtonPanel.Controls.Add($ExportButton)
    # Professional Status Bar Panel
    $StatusBarPanel = New-Object System.Windows.Forms.Panel
    $StatusBarPanel.Location = New-Object System.Drawing.Point(20, 170)
    $StatusBarPanel.Size = New-Object System.Drawing.Size(1460, 35)
    $StatusBarPanel.BackColor = [System.Drawing.Color]::FromArgb(236, 240, 241)
    $StatusBarPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $StatusBarPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    
    # Status Section
    $StatusTitleLabel = New-Object System.Windows.Forms.Label
    $StatusTitleLabel.Text = "STATUS:"
    $StatusTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $StatusTitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(127, 140, 141)
    $StatusTitleLabel.Location = New-Object System.Drawing.Point(10, 9)
    $StatusTitleLabel.Size = New-Object System.Drawing.Size(60, 20)
    $StatusTitleLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left
    $StatusBarPanel.Controls.Add($StatusTitleLabel)
    
    $Global:StatusLabel = New-Object System.Windows.Forms.Label
    $Global:StatusLabel.Text = "Ready"
    $Global:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $Global:StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
    $Global:StatusLabel.Location = New-Object System.Drawing.Point(75, 8)
    $Global:StatusLabel.Size = New-Object System.Drawing.Size(350, 20)
    $Global:StatusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left
    $StatusBarPanel.Controls.Add($Global:StatusLabel)
    
    # Divider 1
    $Divider1 = New-Object System.Windows.Forms.Panel
    $Divider1.Location = New-Object System.Drawing.Point(440, 5)
    $Divider1.Size = New-Object System.Drawing.Size(2, 25)
    $Divider1.BackColor = [System.Drawing.Color]::FromArgb(189, 195, 199)
    $Divider1.Anchor = [System.Windows.Forms.AnchorStyles]::Left
    $StatusBarPanel.Controls.Add($Divider1)
    
    # Credential Section
    $CredTitleLabel = New-Object System.Windows.Forms.Label
    $CredTitleLabel.Text = "USER:"
    $CredTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $CredTitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(127, 140, 141)
    $CredTitleLabel.Location = New-Object System.Drawing.Point(455, 9)
    $CredTitleLabel.Size = New-Object System.Drawing.Size(50, 20)
    $CredTitleLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left
    $StatusBarPanel.Controls.Add($CredTitleLabel)
    
    $Global:CredentialLabel = New-Object System.Windows.Forms.Label
    $Global:CredentialLabel.Text = "Not Connected"
    $Global:CredentialLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $Global:CredentialLabel.ForeColor = [System.Drawing.Color]::FromArgb(231, 76, 60)
    $Global:CredentialLabel.Location = New-Object System.Drawing.Point(510, 8)
    $Global:CredentialLabel.Size = New-Object System.Drawing.Size(450, 20)
    $Global:CredentialLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $StatusBarPanel.Controls.Add($Global:CredentialLabel)
    
    # Divider 2
    $Divider2 = New-Object System.Windows.Forms.Panel
    $Divider2.Location = New-Object System.Drawing.Point(1060, 5)
    $Divider2.Size = New-Object System.Drawing.Size(2, 25)
    $Divider2.BackColor = [System.Drawing.Color]::FromArgb(189, 195, 199)
    $Divider2.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $StatusBarPanel.Controls.Add($Divider2)
    
    # Server Count Section
    $ServerTitleLabel = New-Object System.Windows.Forms.Label
    $ServerTitleLabel.Text = "SERVERS:"
    $ServerTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $ServerTitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(127, 140, 141)
    $ServerTitleLabel.Location = New-Object System.Drawing.Point(1050, 9)
    $ServerTitleLabel.Size = New-Object System.Drawing.Size(80, 20)
    $ServerTitleLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $ServerTitleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $StatusBarPanel.Controls.Add($ServerTitleLabel)

    $ServerCountLabel = New-Object System.Windows.Forms.Label
    $ServerCountLabel.Text = "$($Script:ServerInventory.Count)"
    $ServerCountLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $ServerCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
    $ServerCountLabel.Location = New-Object System.Drawing.Point(1135, 8)
    $ServerCountLabel.Size = New-Object System.Drawing.Size(50, 20)
    $ServerCountLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $ServerCountLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $StatusBarPanel.Controls.Add($ServerCountLabel)

    $ServerTextLabel = New-Object System.Windows.Forms.Label
    $ServerTextLabel.Text = "Loaded"
    $ServerTextLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $ServerTextLabel.ForeColor = [System.Drawing.Color]::FromArgb(127, 140, 141)
    $ServerTextLabel.Location = New-Object System.Drawing.Point(1190, 9)
    $ServerTextLabel.Size = New-Object System.Drawing.Size(60, 20)
    $ServerTextLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $StatusBarPanel.Controls.Add($ServerTextLabel)
    
    $Global:MainForm.Controls.Add($StatusBarPanel)
    
    $ServerCountLabel = New-Object System.Windows.Forms.Label
    $ServerCountLabel.Text = "$($Script:ServerInventory.Count) Servers Loaded"
    $ServerCountLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $ServerCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
    $ServerCountLabel.Location = New-Object System.Drawing.Point(1070, 8)
    $ServerCountLabel.Size = New-Object System.Drawing.Size(200, 20)
    $StatusBarPanel.Controls.Add($ServerCountLabel)
    
    $Global:MainForm.Controls.Add($StatusBarPanel)

    # Add Progress Bar
    # Progress Container with custom height
    # Add Windows-Style Progress Bar
    $Global:ProgressContainer = New-Object System.Windows.Forms.Panel
    $Global:ProgressContainer.Location = New-Object System.Drawing.Point(20, 207)
    $Global:ProgressContainer.Size = New-Object System.Drawing.Size(1460, 35)
    $Global:ProgressContainer.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
    $Global:ProgressContainer.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
    $Global:ProgressContainer.Visible = $false
    $Global:ProgressContainer.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

    # Blue progress bar that fills from left to right
    $Global:ProgressFill = New-Object System.Windows.Forms.Panel
    $Global:ProgressFill.Location = New-Object System.Drawing.Point(0, 0)
    $Global:ProgressFill.Size = New-Object System.Drawing.Size(1, 35)
    $Global:ProgressFill.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $Global:ProgressFill.Dock = [System.Windows.Forms.DockStyle]::Left
    $Global:ProgressContainer.Controls.Add($Global:ProgressFill)

    # Percentage label
    $Global:ProgressLabel = New-Object System.Windows.Forms.Label
    $Global:ProgressLabel.Text = "0%"
    $Global:ProgressLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $Global:ProgressLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $Global:ProgressLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $Global:ProgressLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $Global:ProgressLabel.BackColor = [System.Drawing.Color]::Transparent
    $Global:ProgressContainer.Controls.Add($Global:ProgressLabel)
    $Global:ProgressLabel.BringToFront()

    $Global:MainForm.Controls.Add($Global:ProgressContainer)

    $Global:TabControl = New-Object System.Windows.Forms.TabControl
    $Global:TabControl.Location = New-Object System.Drawing.Point(20, 240)
    $Global:TabControl.Size = New-Object System.Drawing.Size(1460, 640)
    $Global:TabControl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $Global:TabControl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $SummaryTab = New-Object System.Windows.Forms.TabPage
    $SummaryTab.Text = "Welcome"
    $SummaryTab.BackColor = [System.Drawing.Color]::White
    
    # Main Welcome Panel
    $WelcomePanel = New-Object System.Windows.Forms.Panel
    $WelcomePanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $WelcomePanel.BackColor = [System.Drawing.Color]::White
    $WelcomePanel.AutoScroll = $true
    
    # ========== HEADER SECTION ==========
    $HeaderPanel = New-Object System.Windows.Forms.Panel
    $HeaderPanel.Location = New-Object System.Drawing.Point(0, 0)
    $HeaderPanel.Size = New-Object System.Drawing.Size(1440, 100)
    $HeaderPanel.BackColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $HeaderPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    
    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Infrastructure Handover Validation Tool"
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.ForeColor = [System.Drawing.Color]::White
    $TitleLabel.Location = New-Object System.Drawing.Point(30, 15)
    $TitleLabel.AutoSize = $true
    $HeaderPanel.Controls.Add($TitleLabel)
    
    $VersionLabel = New-Object System.Windows.Forms.Label
    $VersionLabel.Text = "Version 2.4  |  Created by: Hisham Nasur - NourNet - MS-TEAM1"
    $VersionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $VersionLabel.ForeColor = [System.Drawing.Color]::FromArgb(189, 195, 199)
    $VersionLabel.Location = New-Object System.Drawing.Point(35, 60)
    $VersionLabel.AutoSize = $true
    $HeaderPanel.Controls.Add($VersionLabel)
    
    $WelcomePanel.Controls.Add($HeaderPanel)
    
    # ========== ROW 1: GETTING STARTED & SERVER INVENTORY ==========
    
    # Getting Started Panel
    $GettingStartedPanel = New-Object System.Windows.Forms.GroupBox
    $GettingStartedPanel.Text = "  Getting Started  "
    $GettingStartedPanel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $GettingStartedPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $GettingStartedPanel.Location = New-Object System.Drawing.Point(30, 120)
    $GettingStartedPanel.Size = New-Object System.Drawing.Size(660, 180)
    $GettingStartedPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    
    # Step 1
    $Step1Panel = New-Object System.Windows.Forms.Panel
    $Step1Panel.Location = New-Object System.Drawing.Point(15, 30)
    $Step1Panel.Size = New-Object System.Drawing.Size(630, 40)
    $Step1Panel.BackColor = [System.Drawing.Color]::White
    $Step1Panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $Step1Number = New-Object System.Windows.Forms.Label
    $Step1Number.Text = "1"
    $Step1Number.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $Step1Number.ForeColor = [System.Drawing.Color]::White
    $Step1Number.BackColor = [System.Drawing.Color]::FromArgb(46, 204, 113)
    $Step1Number.Location = New-Object System.Drawing.Point(5, 5)
    $Step1Number.Size = New-Object System.Drawing.Size(30, 30)
    $Step1Number.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $Step1Panel.Controls.Add($Step1Number)
    
    $Step1Text = New-Object System.Windows.Forms.Label
    $Step1Text.Text = "CONNECT - Click the 'Connect' button to authenticate with domain credentials"
    $Step1Text.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $Step1Text.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $Step1Text.Location = New-Object System.Drawing.Point(45, 9)
    $Step1Text.Size = New-Object System.Drawing.Size(575, 25)
    $Step1Panel.Controls.Add($Step1Text)
    
    $GettingStartedPanel.Controls.Add($Step1Panel)
    
    # Step 2
    $Step2Panel = New-Object System.Windows.Forms.Panel
    $Step2Panel.Location = New-Object System.Drawing.Point(15, 80)
    $Step2Panel.Size = New-Object System.Drawing.Size(630, 40)
    $Step2Panel.BackColor = [System.Drawing.Color]::White
    $Step2Panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $Step2Number = New-Object System.Windows.Forms.Label
    $Step2Number.Text = "2"
    $Step2Number.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $Step2Number.ForeColor = [System.Drawing.Color]::White
    $Step2Number.BackColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
    $Step2Number.Location = New-Object System.Drawing.Point(5, 5)
    $Step2Number.Size = New-Object System.Drawing.Size(30, 30)
    $Step2Number.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $Step2Panel.Controls.Add($Step2Number)
    
    $Step2Text = New-Object System.Windows.Forms.Label
    $Step2Text.Text = "SELECT VALIDATION - Choose: System Utilization, Exchange, AD, or ADFS"
    $Step2Text.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $Step2Text.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $Step2Text.Location = New-Object System.Drawing.Point(45, 9)
    $Step2Text.Size = New-Object System.Drawing.Size(575, 25)
    $Step2Panel.Controls.Add($Step2Text)
    
    $GettingStartedPanel.Controls.Add($Step2Panel)
    
    # Step 3
    $Step3Panel = New-Object System.Windows.Forms.Panel
    $Step3Panel.Location = New-Object System.Drawing.Point(15, 130)
    $Step3Panel.Size = New-Object System.Drawing.Size(630, 40)
    $Step3Panel.BackColor = [System.Drawing.Color]::White
    $Step3Panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $Step3Number = New-Object System.Windows.Forms.Label
    $Step3Number.Text = "3"
    $Step3Number.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $Step3Number.ForeColor = [System.Drawing.Color]::White
    $Step3Number.BackColor = [System.Drawing.Color]::FromArgb(155, 89, 182)
    $Step3Number.Location = New-Object System.Drawing.Point(5, 5)
    $Step3Number.Size = New-Object System.Drawing.Size(30, 30)
    $Step3Number.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $Step3Panel.Controls.Add($Step3Number)
    
    $Step3Text = New-Object System.Windows.Forms.Label
    $Step3Text.Text = "EXPORT RESULTS - Generate professional HTML reports for documentation"
    $Step3Text.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $Step3Text.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $Step3Text.Location = New-Object System.Drawing.Point(45, 9)
    $Step3Text.Size = New-Object System.Drawing.Size(575, 25)
    $Step3Panel.Controls.Add($Step3Text)
    
    $GettingStartedPanel.Controls.Add($Step3Panel)
    
    $WelcomePanel.Controls.Add($GettingStartedPanel)
    
    # Server Inventory Panel
    $InventoryPanel = New-Object System.Windows.Forms.GroupBox
    $InventoryPanel.Text = "  Server Inventory  "
    $InventoryPanel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $InventoryPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $InventoryPanel.Location = New-Object System.Drawing.Point(710, 120)
    $InventoryPanel.Size = New-Object System.Drawing.Size(700, 180)
    $InventoryPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    
    $ServerNumberLabel = New-Object System.Windows.Forms.Label
    $ServerNumberLabel.Text = "$($Script:ServerInventory.Count)"
    $ServerNumberLabel.Font = New-Object System.Drawing.Font("Segoe UI", 60, [System.Drawing.FontStyle]::Bold)
    $ServerNumberLabel.ForeColor = [System.Drawing.Color]::FromArgb(52, 152, 219)
    $ServerNumberLabel.Location = New-Object System.Drawing.Point(280, 40)
    $ServerNumberLabel.Size = New-Object System.Drawing.Size(150, 80)
    $ServerNumberLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $InventoryPanel.Controls.Add($ServerNumberLabel)
    
    $ServerTextLabel = New-Object System.Windows.Forms.Label
    $ServerTextLabel.Text = "Servers Loaded"
    $ServerTextLabel.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $ServerTextLabel.ForeColor = [System.Drawing.Color]::FromArgb(127, 140, 141)
    $ServerTextLabel.Location = New-Object System.Drawing.Point(250, 125)
    $ServerTextLabel.Size = New-Object System.Drawing.Size(200, 25)
    $ServerTextLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $InventoryPanel.Controls.Add($ServerTextLabel)
    
    $FileLocationLabel = New-Object System.Windows.Forms.Label
    $FileLocationLabel.Text = "Source: .\servers.txt"
    $FileLocationLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
    $FileLocationLabel.ForeColor = [System.Drawing.Color]::FromArgb(149, 165, 166)
    $FileLocationLabel.Location = New-Object System.Drawing.Point(270, 150)
    $FileLocationLabel.Size = New-Object System.Drawing.Size(200, 20)
    $FileLocationLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $InventoryPanel.Controls.Add($FileLocationLabel)
    
    $WelcomePanel.Controls.Add($InventoryPanel)
    
    # ========== ROW 2: FEATURES & COLOR LEGEND ==========
    
    # Available Validations Panel
    $FeaturesPanel = New-Object System.Windows.Forms.GroupBox
    $FeaturesPanel.Text = "  Available Validations  "
    $FeaturesPanel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $FeaturesPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $FeaturesPanel.Location = New-Object System.Drawing.Point(30, 320)
    $FeaturesPanel.Size = New-Object System.Drawing.Size(660, 250)
    $FeaturesPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    
    $Features = @(
        @{Text="System Utilization - CPU, Memory, Disk monitoring"; Color=[System.Drawing.Color]::FromArgb(52, 152, 219)},
        @{Text="Exchange Server - Comprehensive health validation"; Color=[System.Drawing.Color]::FromArgb(155, 89, 182)},
        @{Text="Active Directory - 15+ validation checks"; Color=[System.Drawing.Color]::FromArgb(46, 204, 113)},
        @{Text="ADFS - Federation services validation"; Color=[System.Drawing.Color]::FromArgb(230, 126, 34)},
        @{Text="HTML Reports - Professional documentation"; Color=[System.Drawing.Color]::FromArgb(44, 62, 80)}
    )
    
    $YPos = 35
    foreach ($Feature in $Features) {
        $BoxYPos = $YPos + 5
        $FeatureBox = New-Object System.Windows.Forms.Panel
        $FeatureBox.BackColor = $Feature.Color
        $FeatureBox.Location = New-Object System.Drawing.Point(20, $BoxYPos)
        $FeatureBox.Size = New-Object System.Drawing.Size(15, 15)
        $FeaturesPanel.Controls.Add($FeatureBox)
        
        $FeatureLabel = New-Object System.Windows.Forms.Label
        $FeatureLabel.Text = $Feature.Text
        $FeatureLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $FeatureLabel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
        $FeatureLabel.Location = New-Object System.Drawing.Point(45, $YPos)
        $FeatureLabel.Size = New-Object System.Drawing.Size(600, 25)
        $FeaturesPanel.Controls.Add($FeatureLabel)
        
        $YPos += 40
    }
    
    $WelcomePanel.Controls.Add($FeaturesPanel)
    
    # Color Coding Legend Panel
    $LegendPanel = New-Object System.Windows.Forms.GroupBox
    $LegendPanel.Text = "  Result Color Coding  "
    $LegendPanel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $LegendPanel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
    $LegendPanel.Location = New-Object System.Drawing.Point(710, 320)
    $LegendPanel.Size = New-Object System.Drawing.Size(700, 250)
    $LegendPanel.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    
    $ColorItems = @(
        @{Color=$Script:Colors.Success; Text="Success / Normal / OK"},
        @{Color=$Script:Colors.Warning; Text="Warning / Needs Attention"},
        @{Color=$Script:Colors.Error; Text="Error / Critical / Failed"},
        @{Color=$Script:Colors.Info; Text="Information / Details"}
    )
    
    $YPos = 45
    foreach ($Item in $ColorItems) {
        $ColorSample = New-Object System.Windows.Forms.Panel
        $ColorSample.BackColor = $Item.Color
        $ColorSample.Location = New-Object System.Drawing.Point(30, $YPos)
        $ColorSample.Size = New-Object System.Drawing.Size(150, 35)
        $ColorSample.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
        $LegendPanel.Controls.Add($ColorSample)
        
        $LabelYPos = $YPos + 7
        $ColorLabel = New-Object System.Windows.Forms.Label
        $ColorLabel.Text = $Item.Text
        $ColorLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11)
        $ColorLabel.ForeColor = [System.Drawing.Color]::FromArgb(44, 62, 80)
        $ColorLabel.Location = New-Object System.Drawing.Point(200, $LabelYPos)
        $ColorLabel.Size = New-Object System.Drawing.Size(480, 25)
        $LegendPanel.Controls.Add($ColorLabel)
        
        $YPos += 50
    }
    
    $WelcomePanel.Controls.Add($LegendPanel)
    
    $SummaryTab.Controls.Add($WelcomePanel)
    $Global:TabControl.TabPages.Add($SummaryTab)
    $Global:MainForm.Controls.Add($Global:TabControl)
    $Global:MainForm.Add_Shown({$Global:MainForm.Activate()})
    [void]$Global:MainForm.ShowDialog()
}

#endregion

Show-ValidationGUI
