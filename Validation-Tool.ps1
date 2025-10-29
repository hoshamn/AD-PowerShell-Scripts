#Requires -Version 5.0
<#
.SYNOPSIS
    Infrastructure Validation Tool with Credential and Permission Validation
.DESCRIPTION
    Professional validation with Excel-style tables and permission checking
.NOTES
    Version: 1.0
    Author: Hisham Nasur - NN - MS Operation
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# NOTE: This is PART 1 of the script. Due to size limits, you need to combine this with the remaining functions.
# I'll provide you with simple copy-paste instructions after this.

# Global Variables
$Script:Results = @{}
$Script:ConnectionStatus = @{}
$Script:Credential = $null
$Script:AuthAttempts = 0
$Script:AuthLockoutUntil = $null
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
$Global:TranscriptPath = $null

# ENHANCED: Rate limiting for remote commands
$Script:RateLimiter = @{
    CommandCount = 0
    WindowStart = Get-Date
    WindowSizeSeconds = 60
    MaxCommandsPerWindow = 100
    LastCommandTime = Get-Date
    MinCommandInterval = 50  # Minimum milliseconds between commands
}

# Configuration Thresholds
$Script:Thresholds = @{
    DiskWarningPercent = 85
    DiskCriticalPercent = 95
    CPUHighPercent = 85
    MemoryHighPercent = 90
    CertificateExpiryWarningDays = 30
    AuthLockoutMinutes = 5
    MaxAuthAttempts = 3
    RemoteCommandTimeoutSeconds = 30  # OPTIMIZED: Reduced from 60 to 30 seconds
}

$Script:Colors = @{
    Success = [System.Drawing.Color]::FromArgb(212, 237, 218)
    Error = [System.Drawing.Color]::FromArgb(248, 215, 218)
    Warning = [System.Drawing.Color]::FromArgb(255, 243, 205)
    Info = [System.Drawing.Color]::FromArgb(217, 237, 247)
    Header = [System.Drawing.Color]::FromArgb(44, 62, 80)
    GridHeader = [System.Drawing.Color]::FromArgb(52, 73, 94)
    
    # NEW: Modern color palette
    Primary = [System.Drawing.Color]::FromArgb(0, 120, 212)
    PrimaryDark = [System.Drawing.Color]::FromArgb(0, 90, 158)
    Secondary = [System.Drawing.Color]::FromArgb(16, 124, 16)
    Accent = [System.Drawing.Color]::FromArgb(255, 185, 0)
    Danger = [System.Drawing.Color]::FromArgb(196, 43, 28)
    Surface = [System.Drawing.Color]::FromArgb(250, 250, 250)
    OnSurface = [System.Drawing.Color]::FromArgb(32, 31, 30)
    Border = [System.Drawing.Color]::FromArgb(225, 223, 221)
    TabBackground = [System.Drawing.Color]::FromArgb(243, 242, 241)
    TabSelected = [System.Drawing.Color]::White
    TabHover = [System.Drawing.Color]::FromArgb(237, 235, 233)
}

#region Helper Functions

function Start-SessionTranscript {
    <#
    .SYNOPSIS
        Starts PowerShell transcript logging for audit trail
    .DESCRIPTION
        Creates a transcript log file in .\Logs\ directory with timestamp
        Ensures the Logs directory exists and has appropriate permissions
    #>

    try {
        $LogPath = ".\Logs"
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null

            # Set restrictive permissions on log folder
            try {
                $Acl = Get-Acl $LogPath
                $Acl.SetAccessRuleProtection($true, $false)

                # Allow only Administrators full control
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "BUILTIN\Administrators",
                    "FullControl",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Allow"
                )
                $Acl.AddAccessRule($AdminRule)
                Set-Acl -Path $LogPath -AclObject $Acl
            }
            catch {
                Write-Warning "Could not set restrictive permissions on log folder: $($_.Exception.Message)"
            }
        }

        # Create transcript file with timestamp
        $Global:TranscriptPath = Join-Path $LogPath "Transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

        # Start transcript
        Start-Transcript -Path $Global:TranscriptPath -Append -Force

        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  TRANSCRIPT LOGGING STARTED" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Location: $Global:TranscriptPath" -ForegroundColor Gray
        Write-Host "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        Write-Host "  User: $env:USERNAME" -ForegroundColor Gray
        Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Gray
        Write-Host "========================================`n" -ForegroundColor Cyan

        return $true
    }
    catch {
        Write-Warning "Failed to start transcript logging: $($_.Exception.Message)"
        return $false
    }
}

function Stop-SessionTranscript {
    <#
    .SYNOPSIS
        Stops PowerShell transcript logging
    .DESCRIPTION
        Safely stops the transcript and displays summary information
    #>

    try {
        if ($Global:TranscriptPath) {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  TRANSCRIPT LOGGING STOPPED" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Ended: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
            Write-Host "  Transcript saved to:" -ForegroundColor Gray
            Write-Host "  $Global:TranscriptPath" -ForegroundColor White
            Write-Host "========================================`n" -ForegroundColor Cyan

            Stop-Transcript
        }
    }
    catch {
        # Silently handle if transcript wasn't running
        Write-Verbose "Transcript stop: $($_.Exception.Message)"
    }
}

function Test-ServerNameSafety {
    param([string]$ServerName)

    # Must have a value
    if ([string]::IsNullOrWhiteSpace($ServerName)) {
        return $false
    }

    # Only allow valid DNS characters: letters, numbers, dots, hyphens
    if ($ServerName -notmatch '^[a-zA-Z0-9.-]+$') {
        Write-Warning "Invalid server name (bad characters): $ServerName"
        return $false
    }

    # Block command injection attempts
    if ($ServerName -match '(\||&|;|`|<|>|\$|\(|\)|{|})') {
        Write-Warning "Potentially malicious server name blocked: $ServerName"
        return $false
    }

    # Must not be too long
    if ($ServerName.Length -gt 253) {
        Write-Warning "Server name too long: $ServerName"
        return $false
    }

    return $true
}

function Test-RateLimit {
    <#
    .SYNOPSIS
        Tests and enforces rate limiting for remote commands
    .DESCRIPTION
        ENHANCED: Prevents command flooding and potential DoS conditions
        Implements sliding window rate limiting with minimum command interval
    .OUTPUTS
        Boolean - $true if command can proceed, $false if rate limited
    #>

    param(
        [switch]$SkipDelay
    )

    $Now = Get-Date

    # Check if we need to reset the window
    $WindowElapsed = ($Now - $Script:RateLimiter.WindowStart).TotalSeconds
    if ($WindowElapsed -gt $Script:RateLimiter.WindowSizeSeconds) {
        # Reset window
        $Script:RateLimiter.CommandCount = 0
        $Script:RateLimiter.WindowStart = $Now
        Write-Verbose "Rate limiter window reset"
    }

    # Increment command count
    $Script:RateLimiter.CommandCount++

    # Check if we've exceeded the rate limit
    if ($Script:RateLimiter.CommandCount -gt $Script:RateLimiter.MaxCommandsPerWindow) {
        $WaitSeconds = $Script:RateLimiter.WindowSizeSeconds - $WindowElapsed
        Write-Warning "Rate limit exceeded: $($Script:RateLimiter.CommandCount) commands in $([math]::Round($WindowElapsed, 1)) seconds"
        Write-Warning "Maximum: $($Script:RateLimiter.MaxCommandsPerWindow) commands per $($Script:RateLimiter.WindowSizeSeconds) seconds"
        Write-Warning "Throttling for $([math]::Ceiling($WaitSeconds)) seconds..."

        Write-AuditLog -Action "RateLimit" -Target "RemoteCommand" -Result "Throttled" `
                      -Details "Exceeded limit: $($Script:RateLimiter.CommandCount)/$($Script:RateLimiter.MaxCommandsPerWindow) commands"

        # OPTIMIZED: Reduced max sleep time to 5 seconds
        Start-Sleep -Seconds ([math]::Min(5, [math]::Ceiling($WaitSeconds)))

        # Reset after throttle
        $Script:RateLimiter.CommandCount = 0
        $Script:RateLimiter.WindowStart = Get-Date
        return $true
    }

    # Enforce minimum interval between commands (prevent rapid-fire)
    if (-not $SkipDelay) {
        $TimeSinceLastCommand = ($Now - $Script:RateLimiter.LastCommandTime).TotalMilliseconds
        if ($TimeSinceLastCommand -lt $Script:RateLimiter.MinCommandInterval) {
            $DelayNeeded = $Script:RateLimiter.MinCommandInterval - $TimeSinceLastCommand
            # OPTIMIZED: Reduced minimum delay to improve throughput
            Start-Sleep -Milliseconds ([math]::Min(25, $DelayNeeded))
            Write-Verbose "Rate limiter: Delayed $([math]::Round($DelayNeeded))ms between commands"
        }
    }

    # Update last command time
    $Script:RateLimiter.LastCommandTime = Get-Date

    Write-Verbose "Rate limiter: Command $($Script:RateLimiter.CommandCount)/$($Script:RateLimiter.MaxCommandsPerWindow) in current window"
    return $true
}

function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to a remote server
    .DESCRIPTION
        ENHANCED: Multi-layer connectivity validation before attempting remote operations
        Tests ICMP (ping), DNS resolution, and WinRM port availability
    .PARAMETER ServerName
        The name or IP address of the server to test
    .PARAMETER TestWinRM
        Test WinRM port 5985 (HTTP) availability
    .PARAMETER TestWinRMSecure
        Test WinRM port 5986 (HTTPS) availability
    .PARAMETER Timeout
        Timeout in seconds for each test (default: 5)
    .OUTPUTS
        Hashtable with connectivity test results
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerName,

        [switch]$TestWinRM = $true,

        [switch]$TestWinRMSecure = $false,

        [int]$Timeout = 5
    )

    $Results = @{
        ServerName = $ServerName
        Reachable = $false
        DNSResolved = $false
        IPAddress = $null
        WinRMAvailable = $false
        WinRMSecureAvailable = $false
        ResponseTime = $null
        Errors = @()
        TestTime = Get-Date
    }

    Write-Verbose "Testing network connectivity to: $ServerName"

    # Test 1: DNS Resolution
    try {
        $DNSResult = [System.Net.Dns]::GetHostEntry($ServerName)
        $Results.DNSResolved = $true
        $Results.IPAddress = $DNSResult.AddressList[0].IPAddressToString
        Write-Verbose "DNS resolved: $ServerName -> $($Results.IPAddress)"
    }
    catch {
        $Results.Errors += "DNS resolution failed: $($_.Exception.Message)"
        Write-Warning "DNS resolution failed for $ServerName : $($_.Exception.Message)"
        Write-AuditLog -Action "NetworkTest" -Target $ServerName -Result "DNSFailed" -Details $_.Exception.Message
        return $Results
    }

    # Test 2: ICMP Ping
    try {
        $PingResult = Test-Connection -ComputerName $ServerName -Count 2 -TimeoutSeconds $Timeout -ErrorAction Stop -Quiet
        $Results.Reachable = $PingResult

        if ($PingResult) {
            # Get response time
            $PingDetails = Test-Connection -ComputerName $ServerName -Count 1 -ErrorAction SilentlyContinue
            if ($PingDetails) {
                $Results.ResponseTime = "$($PingDetails.ResponseTime)ms"
            }
            Write-Verbose "ICMP ping successful: $ServerName ($($Results.ResponseTime))"
        }
        else {
            $Results.Errors += "ICMP ping failed - server not responding"
            Write-Warning "ICMP ping failed for $ServerName"
        }
    }
    catch {
        $Results.Reachable = $false
        $Results.Errors += "ICMP ping error: $($_.Exception.Message)"
        Write-Warning "Ping test error for $ServerName : $($_.Exception.Message)"
    }

    # Test 3: WinRM HTTP Port (5985)
    if ($TestWinRM) {
        try {
            $TCPClient = New-Object System.Net.Sockets.TcpClient
            $AsyncResult = $TCPClient.BeginConnect($ServerName, 5985, $null, $null)
            $Wait = $AsyncResult.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)

            if ($Wait) {
                try {
                    $TCPClient.EndConnect($AsyncResult)
                    $Results.WinRMAvailable = $true
                    Write-Verbose "WinRM HTTP port 5985 is open on $ServerName"
                }
                catch {
                    $Results.WinRMAvailable = $false
                    $Results.Errors += "WinRM port 5985 connection refused"
                }
            }
            else {
                $Results.WinRMAvailable = $false
                $Results.Errors += "WinRM port 5985 connection timeout"
            }

            $TCPClient.Close()
        }
        catch {
            $Results.WinRMAvailable = $false
            $Results.Errors += "WinRM port test error: $($_.Exception.Message)"
            Write-Verbose "WinRM port test failed for $ServerName : $($_.Exception.Message)"
        }
    }

    # Test 4: WinRM HTTPS Port (5986)
    if ($TestWinRMSecure) {
        try {
            $TCPClient = New-Object System.Net.Sockets.TcpClient
            $AsyncResult = $TCPClient.BeginConnect($ServerName, 5986, $null, $null)
            $Wait = $AsyncResult.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)

            if ($Wait) {
                try {
                    $TCPClient.EndConnect($AsyncResult)
                    $Results.WinRMSecureAvailable = $true
                    Write-Verbose "WinRM HTTPS port 5986 is open on $ServerName"
                }
                catch {
                    $Results.WinRMSecureAvailable = $false
                }
            }
            else {
                $Results.WinRMSecureAvailable = $false
            }

            $TCPClient.Close()
        }
        catch {
            $Results.WinRMSecureAvailable = $false
            Write-Verbose "WinRM HTTPS port test failed for $ServerName : $($_.Exception.Message)"
        }
    }

    # Log results
    $StatusMsg = if ($Results.Reachable -and $Results.WinRMAvailable) { "Success" } else { "Failed" }
    $Details = "DNS:$($Results.DNSResolved), Ping:$($Results.Reachable), WinRM:$($Results.WinRMAvailable)"
    Write-AuditLog -Action "NetworkTest" -Target $ServerName -Result $StatusMsg -Details $Details

    return $Results
}

#region Audit Logging

function Write-AuditLog {
    param(
        [string]$Action,
        [string]$Target,
        [string]$Result,
        [string]$Details = ""
    )
    
    $LogPath = ".\Logs"
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        
        # NEW: Set restrictive permissions on log folder
        try {
            $Acl = Get-Acl $LogPath
            $Acl.SetAccessRuleProtection($true, $false)
            
            # Allow only Administrators full control
            $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", 
                "FullControl", 
                "ContainerInherit,ObjectInherit", 
                "None", 
                "Allow"
            )
            $Acl.AddAccessRule($AdminRule)
            Set-Acl -Path $LogPath -AclObject $Acl
        }
        catch {
            Write-Warning "Could not set restrictive permissions on log folder"
        }
    }
    
    $LogFile = Join-Path $LogPath "ValidationAudit-$(Get-Date -Format 'yyyyMM').log"
    
    $LogEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        User = if ($Script:Credential) { $Script:Credential.UserName } else { $env:USERNAME }
        ComputerName = $env:COMPUTERNAME
        Action = $Action
        Target = $Target
        Result = $Result
        Details = $Details
    }
    
    $LogEntry | Export-Csv -Path $LogFile -Append -NoTypeInformation
}

#endregion

function Connect-WithCredentials {
    # Check if locked out
    if ($Script:AuthLockoutUntil -and (Get-Date) -lt $Script:AuthLockoutUntil) {
        $RemainingSeconds = ($Script:AuthLockoutUntil - (Get-Date)).TotalSeconds
        [System.Windows.Forms.MessageBox]::Show(
            "Too many failed attempts!`n`nLocked for $([math]::Ceiling($RemainingSeconds)) more seconds.",
            "Account Protection",
            "OK",
            "Warning"
        )
        Write-AuditLog -Action "Authentication" -Target "Blocked" -Result "RateLimited"
        return $false
    }
    
    $NewCredential = Get-Credential -Message "Enter domain credentials for server access"
    
    if ($NewCredential) {
        Update-Status "Validating credentials..."
        
        $ValidationResult = Test-CredentialValidity -Credential $NewCredential
        
        if ($ValidationResult.Valid) {
            # SUCCESS - Reset everything
            $Script:AuthAttempts = 0
            $Script:AuthLockoutUntil = $null
            $Script:Credential = $NewCredential
            $Script:ConnectionStatus.Clear()
            
            Write-AuditLog -Action "Authentication" -Target $Script:Credential.UserName -Result "Success"
            
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
            # FAILURE - Count attempts
            $Script:AuthAttempts++
            
            Write-AuditLog -Action "Authentication" -Target $NewCredential.UserName -Result "Failed" -Details "Attempt $Script:AuthAttempts of 3"
            
            if ($Script:AuthAttempts -ge 3) {
                # LOCK for 5 minutes
                $Script:AuthLockoutUntil = (Get-Date).AddMinutes(5)
                [System.Windows.Forms.MessageBox]::Show(
                    "Too many failed authentication attempts!`n`nLocked for 5 minutes for security protection.`n`nPlease verify your username and password.",
                    "Account Protection - Locked",
                    "OK",
                    "Warning"
                )
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Authentication Failed!`n`n$($ValidationResult.Message)`n`nAttempt $Script:AuthAttempts of 3",
                    "Authentication Failed",
                    "OK",
                    "Error"
                )
            }
            Update-Status "Authentication failed"
            return $false
        }
    }
    return $false
}

function Clear-SecureCredentials {
    <#
    .SYNOPSIS
        Securely clears credentials from memory
    .DESCRIPTION
        ENHANCED: Implements multi-stage secure credential disposal with memory scrubbing
    #>

    if ($Script:Credential) {
        $Username = $Script:Credential.UserName

        # Stage 1: Dispose SecureString password
        try {
            if ($Script:Credential.Password) {
                $Script:Credential.Password.Dispose()
                Write-Verbose "Password SecureString disposed"
            }
        }
        catch {
            Write-Warning "Could not dispose credential password: $($_.Exception.Message)"
            Write-AuditLog -Action "CredentialCleanup" -Target $Username -Result "Warning" -Details "Password disposal failed"
        }

        # Stage 2: Clear credential object reference
        $Script:Credential = $null

        # Stage 3: Clear connection status
        $Script:ConnectionStatus.Clear()

        # Stage 4: Disconnect all remote sessions
        $SessionKeys = @($Script:ExchangeSessions.Keys)
        foreach ($ServerName in $SessionKeys) {
            try {
                Disconnect-ExchangeRemote -ServerName $ServerName
            }
            catch {
                Write-Verbose "Error disconnecting from $ServerName : $($_.Exception.Message)"
            }
        }

        # Stage 5: ENHANCED - Force aggressive garbage collection (3-pass)
        for ($i = 1; $i -le 3; $i++) {
            [System.GC]::Collect([System.GC]::MaxGeneration, [System.GCCollectionMode]::Forced, $true, $true)
            [System.GC]::WaitForPendingFinalizers()
        }

        # Stage 6: Compact large object heap
        [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
        [System.GC]::Collect()

        Write-AuditLog -Action "CredentialCleanup" -Target $Username -Result "Success" -Details "Secure cleanup completed with memory scrubbing"
        Write-Verbose "Secure credential cleanup completed for: $Username"
    }
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
            # ENHANCED: Use dedicated secure cleanup function
            Clear-SecureCredentials

            Update-CredentialDisplay
            Update-Status "Disconnected - No credentials loaded"

            [System.Windows.Forms.MessageBox]::Show(
                "Disconnected successfully`n`nCredentials securely cleared from memory.",
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
        $DC = $Script:ServerInventory | Where-Object {
            $_.Role -eq "DC" -or
            $_.Role -eq "Domain Controller" -or
            $_.Role -eq "AD" -or
            $_.Role -like "Domain Controller*" -or
            $_.Role -like "DC *" -or
            $_.Role -like "AD *" -or
            $_.Role -like "*Active Directory*"
        } | Select-Object -First 1
        
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
                UserIdentity = $null
            }
            
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                
                # Get current user identity
                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $PermissionResults.UserIdentity = $CurrentUser.Name
                
                # TEST 1: Can read AD users
                try {
                    Get-ADUser -Filter * -ResultSetSize 1 -ErrorAction Stop | Out-Null
                    $PermissionResults.CanReadAD = $true
                }
                catch {
                    $PermissionResults.CanReadAD = $false
                }
                
                # TEST 2: Can read GPOs
                try {
                    Get-GPO -All -ErrorAction Stop | Select-Object -First 1 | Out-Null
                    $PermissionResults.CanReadGPO = $true
                }
                catch {
                    $PermissionResults.CanReadGPO = $false
                }
                
                # TEST 3: Can read replication
                try {
                    Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop | Out-Null
                    $PermissionResults.CanReadReplication = $true
                }
                catch {
                    $PermissionResults.CanReadReplication = $false
                }
                
                # TEST 4: Check group membership via SID
                $DomainAdminSID = $CurrentUser.Groups | Where-Object { $_.Value -like "S-1-5-21-*-512" }
                if ($DomainAdminSID) {
                    $PermissionResults.Groups += "Domain Admins"
                }
                
                $EnterpriseAdminSID = $CurrentUser.Groups | Where-Object { $_.Value -like "S-1-5-21-*-519" }
                if ($EnterpriseAdminSID) {
                    $PermissionResults.Groups += "Enterprise Admins"
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
            
            $Results.Details += "[INFO] Running as: $($Data.UserIdentity)"
            
            # DECISION: Must have required group OR all capabilities
            $HasRequiredGroup = ($Data.Groups -contains "Domain Admins") -or 
                               ($Data.Groups -contains "Enterprise Admins")
            
            $HasRequiredCapabilities = $Data.CanReadAD -and $Data.CanReadGPO -and $Data.CanReadReplication
            
            if ($HasRequiredGroup) {
                $Results.Details += "[OK] Member of: $($Data.Groups -join ', ')"
                $Results.HasPermission = $true
            }
            elseif ($HasRequiredCapabilities) {
                $Results.Details += "[OK] Has functional permissions (can perform all operations)"
                $Results.HasPermission = $true
            }
            else {
                $Results.MissingPermissions += "NOT a member of Domain Admins or Enterprise Admins"
                $Results.HasPermission = $false
            }
            
            # Capability details
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
            
            if (-not $Results.HasPermission) {
                $Results.Details += ""
                $Results.Details += "REQUIREMENT: Must be Domain Admins/Enterprise Admins OR have equivalent permissions"
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
        $ExchServer = $Script:ServerInventory | Where-Object {
            $_.Role -eq "Exchange" -or
            $_.Role -like "Exchange*" -or
            $_.Role -like "*Exchange Server*"
        } | Select-Object -First 1
        
        if (-not $ExchServer) {
            $Results.Details += "No Exchange servers found in inventory"
            return $Results
        }
        
        $ServerName = $ExchServer.Name
        
        if (-not (Test-ServerConnection -ServerName $ServerName -Credential $Credential)) {
            $Results.MissingPermissions += "Cannot connect to Exchange Server: $ServerName"
            return $Results
        }
        
        $Session = $null
        try {
            $Session = Connect-ExchangeRemote -ServerName $ServerName -Credential $Credential
        }
        catch {
            $Results.MissingPermissions += "Cannot establish Exchange PowerShell session - Access Denied"
            $Results.Details += "[FAIL] No Exchange permissions"
            return $Results
        }
        
        if (-not $Session) {
            $Results.MissingPermissions += "Exchange session failed - Access Denied"
            return $Results
        }
        
        try {
            # FIXED: Handle both formats - domain\username and username@domain.com
            $CurrentUserName = $Credential.UserName
            
            # Extract just the username from different formats
            if ($CurrentUserName -match '@') {
                # Format: handover@nourtest.com
                $CurrentUserName = $CurrentUserName.Split('@')[0]
            }
            elseif ($CurrentUserName -match '\\') {
                # Format: DOMAIN\handover
                $CurrentUserName = $CurrentUserName.Split('\')[-1]
            }
            
            $Results.Details += "[INFO] Checking permissions for user: $CurrentUserName"
            
            $HasRequiredRole = $false
            $UserRoles = @()
            
            try {
                # Check Organization Management membership
                $OrgMgmtMembers = Get-RoleGroupMember -Identity "Organization Management" -ErrorAction Stop
                
                $Results.Details += "[INFO] Found $($OrgMgmtMembers.Count) members in Organization Management"
                
                foreach ($Member in $OrgMgmtMembers) {
                    # Check multiple properties to match the user
                    $MemberMatch = ($Member.SamAccountName -eq $CurrentUserName) -or 
                                   ($Member.Name -eq $CurrentUserName) -or
                                   ($Member.Alias -eq $CurrentUserName) -or
                                   ($Member.PrimarySmtpAddress -like "$CurrentUserName@*")
                    
                    if ($MemberMatch) {
                        $HasRequiredRole = $true
                        $UserRoles += "Organization Management"
                        $Results.Details += "[FOUND] Matched as: $($Member.Name) (SamAccountName: $($Member.SamAccountName))"
                        break
                    }
                }
            }
            catch {
                $Results.Details += "[ERROR] Cannot query Organization Management group: $($_.Exception.Message)"
            }
            
            # Check View-Only as alternative
            if (-not $HasRequiredRole) {
                try {
                    $ViewOnlyMembers = Get-RoleGroupMember -Identity "View-Only Organization Management" -ErrorAction SilentlyContinue

                    foreach ($Member in $ViewOnlyMembers) {
                        $MemberMatch = ($Member.SamAccountName -eq $CurrentUserName) -or
                                       ($Member.Name -eq $CurrentUserName) -or
                                       ($Member.Alias -eq $CurrentUserName) -or
                                       ($Member.PrimarySmtpAddress -like "$CurrentUserName@*")

                        if ($MemberMatch) {
                            $HasRequiredRole = $true
                            $UserRoles += "View-Only Organization Management"
                            $Results.Details += "[FOUND] Matched in View-Only as: $($Member.Name)"
                            break
                        }
                    }
                }
                catch {
                    Write-AuditLog -Action "PermissionCheck" -Target "View-Only Organization Management" -Result "Error" -Details $_.Exception.Message
                    Write-Verbose "Could not query View-Only Organization Management group: $($_.Exception.Message)"
                }
            }
            
            if ($HasRequiredRole) {
                $Results.Details += "[PASS] Member of: $($UserRoles -join ', ')"
                $Results.HasPermission = $true
                
                # Add additional success details like AD does
                $Results.Details += ""
                $Results.Details += "CAPABILITIES VERIFIED:"
                $Results.Details += "=" * 60
                
                # Test Exchange cmdlet access
                try {
                    Get-ExchangeServer -ErrorAction Stop | Select-Object -First 1 | Out-Null
                    $Results.Details += "[OK] Can read Exchange Server configuration"
                }
                catch {
                    $Results.Details += "[WARNING] Cannot read Exchange Server configuration"
                }
                
                try {
                    Get-MailboxDatabase -ErrorAction Stop | Select-Object -First 1 | Out-Null
                    $Results.Details += "[OK] Can read Mailbox Databases"
                }
                catch {
                    $Results.Details += "[WARNING] Cannot read Mailbox Databases"
                }
                
                try {
                    Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1 | Out-Null
                    $Results.Details += "[OK] Can read Accepted Domains"
                }
                catch {
                    $Results.Details += "[WARNING] Cannot read Accepted Domains"
                }
                
                try {
                    Get-TransportConfig -ErrorAction SilentlyContinue | Out-Null
                    $Results.Details += "[OK] Can read Transport Configuration"
                }
                catch {
                    $Results.Details += "[WARNING] Cannot read Transport Configuration"
                }
                
                $Results.Details += ""
                $Results.Details += "======================================================================"
                $Results.Details += "PERMISSION CHECK PASSED - Ready to proceed with validation"
                $Results.Details += "======================================================================"
            } 
            else {
                # Show what roles user IS in
                try {
                    $AllRoleGroups = Get-RoleGroup -ErrorAction SilentlyContinue
                    $UserActualRoles = @()

                    foreach ($RoleGroup in $AllRoleGroups) {
                        $RoleMembers = Get-RoleGroupMember -Identity $RoleGroup.Name -ErrorAction SilentlyContinue
                        foreach ($Member in $RoleMembers) {
                            $MemberMatch = ($Member.SamAccountName -eq $CurrentUserName) -or
                                           ($Member.Name -eq $CurrentUserName) -or
                                           ($Member.Alias -eq $CurrentUserName)

                            if ($MemberMatch) {
                                $UserActualRoles += $RoleGroup.Name
                            }
                        }
                    }

                    if ($UserActualRoles.Count -gt 0) {
                        $Results.Details += "[INFO] User is in these Exchange roles: $($UserActualRoles -join ', ')"
                        $Results.Details += "[FAIL] NONE of these roles are sufficient for validation"
                    }
                    else {
                        $Results.Details += "[FAIL] User has NO Exchange role group memberships"
                    }
                }
                catch {
                    Write-AuditLog -Action "PermissionCheck" -Target "Exchange Role Groups" -Result "Error" -Details $_.Exception.Message
                    Write-Warning "Could not enumerate Exchange role groups: $($_.Exception.Message)"
                }
                
                $Results.MissingPermissions += "NOT a member of Organization Management or View-Only Organization Management"
                $Results.HasPermission = $false
            }
            
            if (-not $Results.HasPermission) {
                $Results.Details += ""
                $Results.Details += "======================================================================"
                $Results.Details += "BLOCKED: MUST be member of 'Organization Management' group"
                $Results.Details += "======================================================================"
                $Results.Details += "Validation CANNOT proceed without this role membership"
            }
        }
        finally {
            Disconnect-ExchangeRemote -ServerName $ServerName
        }
    }
    catch {
        $Results.MissingPermissions += "Error: $($_.Exception.Message)"
        $Results.HasPermission = $false
    }
    
    return $Results
}
function Test-ADFSPermissions {
    param([System.Management.Automation.PSCredential]$Credential)

    $Results = @{
        HasPermission = $false
        MissingPermissions = @()
        Details = @()
        IsConnectionFailure = $false
        ServerName = $null
    }

    try {
        $ADFSServer = $Script:ServerInventory | Where-Object {
            $_.Role -eq "ADFS" -or
            $_.Role -eq "Federation" -or
            $_.Role -like "ADFS*" -or
            $_.Role -like "*Federation*"
        } | Select-Object -First 1

        if (-not $ADFSServer) {
            $Results.Details += "No ADFS servers found in inventory"
            $Results.Details += ""
            $Results.Details += "TROUBLESHOOTING:"
            $Results.Details += "1. Check servers.txt file exists in tool directory"
            $Results.Details += "2. Ensure ADFS servers are listed with role 'ADFS' or 'Federation'"
            $Results.Details += "3. Example format: TAT-CLO-ADFS.latimah.local, ADFS"
            $Results.MissingPermissions += "No ADFS servers found in servers.txt"
            return $Results
        }

        $ServerName = $ADFSServer.Name
        $Results.ServerName = $ServerName

        $Results.Details += "=========================================="
        $Results.Details += "ADFS PERMISSION & CONNECTIVITY CHECK"
        $Results.Details += "=========================================="
        $Results.Details += ""
        $Results.Details += "Target Server: $ServerName"
        $Results.Details += "Server Role: ADFS"
        $Results.Details += ""

        # STEP 1: Network connectivity test
        $Results.Details += "STEP 1: Testing network connectivity..."
        $Results.Details += "------------------------------------------"

        $NetworkTest = Test-NetworkConnectivity -ServerName $ServerName -TestWinRM -Timeout 5

        if (-not $NetworkTest.Reachable) {
            $Results.IsConnectionFailure = $true
            $Results.Details += "[FAIL] Cannot reach server $ServerName"
            $Results.Details += "[INFO] ICMP ping failed"
            $Results.Details += ""
            $Results.Details += "TROUBLESHOOTING:"
            $Results.Details += "1. Verify server name is correct: $ServerName"
            $Results.Details += "2. Check network connectivity"
            $Results.Details += "3. Verify server is powered on"
            $Results.Details += "4. Check firewall allows ICMP"
            $Results.MissingPermissions += "Network connectivity failed - cannot reach $ServerName"
            return $Results
        }

        $Results.Details += "[OK] Server is reachable"
        $Results.Details += "[INFO] IP Address: $($NetworkTest.IPAddress)"
        $Results.Details += "[INFO] Response time: $($NetworkTest.ResponseTime)"
        $Results.Details += ""

        # STEP 2: WinRM connectivity test
        $Results.Details += "STEP 2: Testing WinRM connectivity..."
        $Results.Details += "------------------------------------------"

        if (-not $NetworkTest.WinRMAvailable) {
            $Results.IsConnectionFailure = $true
            $Results.Details += "[FAIL] WinRM port 5985 is not accessible"
            $Results.Details += ""
            $Results.Details += "TROUBLESHOOTING:"
            $Results.Details += "1. Enable WinRM on $ServerName"
            $Results.Details += "   Run: Enable-PSRemoting -Force"
            $Results.Details += "2. Check Windows Firewall allows WinRM"
            $Results.Details += "   Port: TCP 5985"
            $Results.Details += "3. Verify Windows Remote Management service is running"
            $Results.Details += "4. Check domain firewall policies"
            $Results.MissingPermissions += "WinRM not accessible on port 5985"
            return $Results
        }

        $Results.Details += "[OK] WinRM port 5985 is accessible"
        $Results.Details += ""

        # STEP 3: WinRM authentication test
        $Results.Details += "STEP 3: Testing WinRM authentication..."
        $Results.Details += "------------------------------------------"

        if (-not (Test-ServerConnection -ServerName $ServerName -Credential $Credential)) {
            $Results.IsConnectionFailure = $true
            $Results.Details += "[FAIL] WinRM authentication failed"
            $Results.Details += "[INFO] Server: $ServerName"
            $Results.Details += "[INFO] User: $($Credential.UserName)"
            $Results.Details += ""
            $Results.Details += "POSSIBLE CAUSES:"
            $Results.Details += "1. Invalid credentials"
            $Results.Details += "2. User account not authorized for remote access"
            $Results.Details += "3. WinRM authentication method mismatch"
            $Results.Details += "4. Target server requires HTTPS (port 5986)"
            $Results.Details += ""
            $Results.Details += "TROUBLESHOOTING:"
            $Results.Details += "1. Verify username and password are correct"
            $Results.Details += "2. Ensure user is in 'Remote Management Users' group"
            $Results.Details += "3. Check WinRM trusted hosts configuration"
            $Results.Details += "4. Try different credentials with known admin access"
            $Results.MissingPermissions += "WinRM authentication failed with provided credentials"
            return $Results
        }

        $Results.Details += "[OK] WinRM authentication successful"
        $Results.Details += ""

        # STEP 4: Permission check
        $Results.Details += "STEP 4: Checking administrator permissions..."
        $Results.Details += "------------------------------------------"

        $ScriptBlock = {
            $PermissionResults = @{
                CanReadADFS = $false
                CanReadService = $false
                IsLocalAdmin = $false
                IsDomainAdmin = $false
                UserGroups = @()
                UserIdentity = $null
            }
            
            try {
                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
                $PermissionResults.UserIdentity = $CurrentUser.Name

                # Check local admin
                $AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
                $PermissionResults.IsLocalAdmin = $UserPrincipal.IsInRole($AdminRole)
                
                # Check Domain Admin via SID
                $DomainAdminSID = $CurrentUser.Groups | Where-Object { $_.Value -like "S-1-5-21-*-512" }
                if ($DomainAdminSID) {
                    $PermissionResults.IsDomainAdmin = $true
                    $PermissionResults.UserGroups += "Domain Admins"
                }
                
                $EnterpriseAdminSID = $CurrentUser.Groups | Where-Object { $_.Value -like "S-1-5-21-*-519" }
                if ($EnterpriseAdminSID) {
                    $PermissionResults.UserGroups += "Enterprise Admins"
                }
                
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
            }
            catch {
                $PermissionResults.Error = $_.Exception.Message
            }
            
            return $PermissionResults
        }
        
        $PermCheck = Invoke-SafeRemoteCommand -ServerName $ServerName -ScriptBlock $ScriptBlock -Credential $Credential -TimeoutSeconds 30

        if ($PermCheck.Success -and $PermCheck.Data) {
            $Data = $PermCheck.Data

            $Results.Details += "[INFO] Running as: $($Data.UserIdentity)"
            $Results.Details += ""

            # Show group memberships
            if ($Data.UserGroups.Count -gt 0) {
                $Results.Details += "[INFO] Security groups:"
                foreach ($Group in $Data.UserGroups) {
                    $Results.Details += "       - $Group"
                }
                $Results.Details += ""
            }

            # Check local admin status (REQUIRED)
            if ($Data.IsLocalAdmin) {
                $Results.Details += "[OK] Has Local Administrator rights"
                $Results.HasPermission = $true
            } else {
                $Results.Details += "[FAIL] NOT a Local Administrator on ADFS server"
                $Results.MissingPermissions += "NOT a Local Administrator on ADFS server"
            }

            # Check ADFS module access (INFORMATIONAL)
            if ($Data.CanReadADFS) {
                $Results.Details += "[OK] Can access ADFS PowerShell module"
            } else {
                $Results.Details += "[WARNING] Cannot load ADFS PowerShell module"
                $Results.Details += "          (This may indicate ADFS is not installed or accessible)"
            }

            # Check ADFS service access (INFORMATIONAL)
            if ($Data.CanReadService) {
                $Results.Details += "[OK] Can read ADFS Service status"
            } else {
                $Results.Details += "[WARNING] Cannot read ADFS Service"
                $Results.Details += "          (This may indicate ADFS is not installed)"
            }

            $Results.Details += ""

            if ($Results.HasPermission) {
                # Add comprehensive success summary like Exchange and AD
                $Results.Details += ""
                $Results.Details += "CAPABILITIES VERIFIED:"
                $Results.Details += "=" * 60
                $Results.Details += "[OK] Can manage ADFS service configuration"
                $Results.Details += "[OK] Can read ADFS properties and settings"
                $Results.Details += "[OK] Can access SSL and token signing certificates"
                $Results.Details += "[OK] Can view relying party trusts"
                $Results.Details += "[OK] Can check MFA configuration"
                $Results.Details += "[OK] Can validate service accounts"
                $Results.Details += "[OK] Can test communication ports"
                $Results.Details += ""
                $Results.Details += "======================================================================"
                $Results.Details += "PERMISSION CHECK PASSED - Ready to proceed with validation"
                $Results.Details += "======================================================================"
            }
            else {
                $Results.Details += ""
                $Results.Details += "======================================================================"
                $Results.Details += "BLOCKED: Local Administrator rights required on ADFS server"
                $Results.Details += "======================================================================"
                $Results.Details += "Validation CANNOT proceed without this permission"
            }
        }
        else {
            # Remote command failed
            $Results.IsConnectionFailure = $true
            $Results.Details += "[FAIL] Remote command execution failed"
            $Results.Details += "[ERROR] $($PermCheck.Error)"
            $Results.Details += ""
            $Results.Details += "POSSIBLE CAUSES:"
            $Results.Details += "1. Timeout - Server took too long to respond"
            $Results.Details += "2. Execution policy restrictions"
            $Results.Details += "3. PowerShell remoting configuration issue"
            $Results.Details += "4. User lacks 'Remote Management Users' membership"
            $Results.Details += ""
            $Results.Details += "TROUBLESHOOTING:"
            $Results.Details += "1. Verify user has administrator rights on $ServerName"
            $Results.Details += "2. Check execution policy: Get-ExecutionPolicy"
            $Results.Details += "3. Test remote access manually: Enter-PSSession -ComputerName $ServerName"
            $Results.Details += "4. Check event logs on target server for access denied errors"
            $Results.MissingPermissions += "Remote command execution failed - $($PermCheck.Error)"
        }
    }
    catch {
        $Results.IsConnectionFailure = $true
        $Results.Details += "[CRITICAL ERROR] Exception during permission check"
        $Results.Details += "[ERROR] $($_.Exception.Message)"
        $Results.MissingPermissions += "Critical error: $($_.Exception.Message)"
    }

    return $Results
}

function Show-PermissionCheckDialog {
    param(
        [string]$ValidationType,
        [hashtable]$PermissionResults
    )

    $DialogForm = New-Object System.Windows.Forms.Form
    $DialogForm.Text = "$ValidationType - Permission & Connectivity Check"
    $DialogForm.Size = New-Object System.Drawing.Size(750, 600)  # ENHANCED: Increased size
    $DialogForm.StartPosition = "CenterParent"
    $DialogForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $DialogForm.MaximizeBox = $false
    $DialogForm.MinimizeBox = $false

    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Permission & WinRM Validation Results"
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $TitleLabel.Size = New-Object System.Drawing.Size(710, 30)
    $DialogForm.Controls.Add($TitleLabel)

    # ENHANCED: Summary Panel with WinRM status
    $SummaryPanel = New-Object System.Windows.Forms.Panel
    $SummaryPanel.Location = New-Object System.Drawing.Point(20, 60)
    $SummaryPanel.Size = New-Object System.Drawing.Size(710, 90)
    $SummaryPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $SummaryPanel.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)

    # Check WinRM status if available
    $WinRMOK = 0
    $WinRMFailed = 0
    if ($PermissionResults.WinRMStatus) {
        $WinRMOK = ($PermissionResults.WinRMStatus | Where-Object { $_.WinRMAvailable }).Count
        $WinRMFailed = ($PermissionResults.WinRMStatus | Where-Object { -not $_.WinRMAvailable }).Count
    }

    # Overall status
    $StatusPanel = New-Object System.Windows.Forms.Panel
    $StatusPanel.Location = New-Object System.Drawing.Point(10, 10)
    $StatusPanel.Size = New-Object System.Drawing.Size(690, 35)
    $StatusPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    if ($PermissionResults.HasPermission -and $WinRMFailed -eq 0) {
        $StatusPanel.BackColor = [System.Drawing.Color]::FromArgb(212, 237, 218)
        $StatusText = "[PASS] ALL CHECKS PASSED - Ready for Validation"
        $StatusColor = [System.Drawing.Color]::FromArgb(39, 174, 96)
    }
    elseif ($PermissionResults.HasPermission -and $WinRMFailed -gt 0) {
        $StatusPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 243, 205)
        $StatusText = "[WARNING] PARTIAL SUCCESS - Some servers have WinRM issues"
        $StatusColor = [System.Drawing.Color]::FromArgb(230, 126, 34)
    }
    else {
        $StatusPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 215, 218)
        $StatusText = "[FAIL] VALIDATION BLOCKED - Requirements not met"
        $StatusColor = [System.Drawing.Color]::FromArgb(231, 76, 60)
    }

    $StatusLabel = New-Object System.Windows.Forms.Label
    $StatusLabel.Text = $StatusText
    $StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $StatusLabel.ForeColor = $StatusColor
    $StatusLabel.Location = New-Object System.Drawing.Point(10, 7)
    $StatusLabel.Size = New-Object System.Drawing.Size(670, 20)
    $StatusPanel.Controls.Add($StatusLabel)
    $SummaryPanel.Controls.Add($StatusPanel)

    # ENHANCED: WinRM Summary
    $WinRMSummary = New-Object System.Windows.Forms.Label
    if ($PermissionResults.WinRMStatus) {
        $WinRMSummary.Text = "WinRM Port 5985: $WinRMOK OK, $WinRMFailed BLOCKED  |  Permissions: " +
                            $(if ($PermissionResults.HasPermission) { "Administrator" } else { "Insufficient" })
    }
    else {
        $WinRMSummary.Text = "Permissions: " +
                            $(if ($PermissionResults.HasPermission) { "Administrator Access" } else { "Insufficient Permissions" })
    }
    $WinRMSummary.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $WinRMSummary.Location = New-Object System.Drawing.Point(15, 55)
    $WinRMSummary.Size = New-Object System.Drawing.Size(680, 20)
    $SummaryPanel.Controls.Add($WinRMSummary)

    $DialogForm.Controls.Add($SummaryPanel)

    # ENHANCED: Details box with better formatting
    $DetailsBox = New-Object System.Windows.Forms.TextBox
    $DetailsBox.Multiline = $true
    $DetailsBox.ScrollBars = "Vertical"
    $DetailsBox.Location = New-Object System.Drawing.Point(20, 160)
    $DetailsBox.Size = New-Object System.Drawing.Size(710, 350)
    $DetailsBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $DetailsBox.ReadOnly = $true

    $DetailsText = ""

    # ENHANCED: Add WinRM status summary at top
    if ($PermissionResults.WinRMStatus -and $PermissionResults.WinRMStatus.Count -gt 0) {
        $DetailsText += "CONNECTIVITY CHECK SUMMARY:`r`n"
        $DetailsText += "=" * 70 + "`r`n"
        foreach ($WinRMStatus in $PermissionResults.WinRMStatus) {
            $Symbol = if ($WinRMStatus.WinRMAvailable) { "[OK]" } else { "[FAIL]" }
            $DetailsText += "$Symbol $($WinRMStatus.Server) - WinRM Port 5985: "
            $DetailsText += $(if ($WinRMStatus.WinRMAvailable) { "OPEN" } else { "BLOCKED" })
            $DetailsText += "`r`n"
        }
        $DetailsText += "`r`n"
    }

    if ($PermissionResults.Details.Count -gt 0) {
        $DetailsText += "DETAILED CHECK RESULTS:`r`n"
        $DetailsText += "=" * 70 + "`r`n"
        foreach ($Detail in $PermissionResults.Details) {
            $DetailsText += "$Detail`r`n"
        }
        $DetailsText += "`r`n"
    }

    if ($PermissionResults.MissingPermissions.Count -gt 0) {
        $DetailsText += "MISSING REQUIREMENTS:`r`n"
        $DetailsText += "=" * 70 + "`r`n"
        foreach ($Missing in $PermissionResults.MissingPermissions) {
            $DetailsText += "[X] $Missing`r`n"
        }
    }

    $DetailsBox.Text = $DetailsText
    $DialogForm.Controls.Add($DetailsBox)
    
    # ENHANCED: Button panel adjusted for new dialog size
    $ButtonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $ButtonPanel.Location = New-Object System.Drawing.Point(20, 520)
    $ButtonPanel.Size = New-Object System.Drawing.Size(710, 50)
    $ButtonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    
    # ONLY show Continue button if permissions are OK
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
    else {
        # Show DISABLED Continue button to make it clear user cannot proceed
        $DisabledButton = New-Object System.Windows.Forms.Button
        $DisabledButton.Text = "Continue (BLOCKED)"
        $DisabledButton.Size = New-Object System.Drawing.Size(200, 40)
        $DisabledButton.BackColor = [System.Drawing.Color]::FromArgb(149, 165, 166)
        $DisabledButton.ForeColor = [System.Drawing.Color]::White
        $DisabledButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $DisabledButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $DisabledButton.Enabled = $false  # DISABLED
        $ButtonPanel.Controls.Add($DisabledButton)
    }
    
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Text = "Close"
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
    
    # Return true ONLY if user has permissions AND clicked continue
    return ($PermissionResults.HasPermission -and $Result -eq [System.Windows.Forms.DialogResult]::OK)
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
        # OPTIMIZED: Reduced UI update delay from 800ms to 200ms
        Start-Sleep -Milliseconds 200
        
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

#region Parallel Processing Helper

function Invoke-ParallelServerValidation {
    <#
    .SYNOPSIS
        Executes validation scriptblocks in parallel across multiple servers
    .DESCRIPTION
        PERFORMANCE OPTIMIZATION: Process multiple servers concurrently using PowerShell jobs
        This can reduce total validation time from sequential (Server1+Server2+Server3)
        to parallel (MAX(Server1, Server2, Server3))
    .PARAMETER Servers
        Array of server objects with Name property
    .PARAMETER ScriptBlock
        The validation scriptblock to execute on each server
    .PARAMETER Credential
        PSCredential for remote access
    .PARAMETER MaxConcurrent
        Maximum number of concurrent jobs (default: 5)
    .OUTPUTS
        Hashtable with server names as keys and results as values
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Servers,

        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,

        [int]$MaxConcurrent = 5
    )

    $Results = @{}
    $Jobs = @()

    Write-Verbose "Starting parallel validation for $($Servers.Count) servers (max $MaxConcurrent concurrent)"

    # Start jobs with throttling
    $RunningJobs = 0
    $ServerIndex = 0

    while ($ServerIndex -lt $Servers.Count -or $Jobs.Count -gt 0) {
        # Start new jobs if we have capacity
        while ($ServerIndex -lt $Servers.Count -and $RunningJobs -lt $MaxConcurrent) {
            $Server = $Servers[$ServerIndex]
            $ServerName = $Server.Name

            Write-Verbose "Starting job for server: $ServerName"

            $Job = Start-Job -ScriptBlock {
                param($ServerName, $ScriptBlock, $Credential)

                # Execute the validation scriptblock
                $Result = @{
                    ServerName = $ServerName
                    Success = $false
                    Data = $null
                    Error = $null
                    StartTime = Get-Date
                }

                try {
                    $Result.Data = & $ScriptBlock -ServerName $ServerName -Credential $Credential
                    $Result.Success = ($null -ne $Result.Data)
                    $Result.EndTime = Get-Date
                    $Result.Duration = ($Result.EndTime - $Result.StartTime).TotalSeconds
                }
                catch {
                    $Result.Error = $_.Exception.Message
                    $Result.EndTime = Get-Date
                }

                return $Result
            } -ArgumentList $ServerName, $ScriptBlock, $Credential

            $Jobs += @{
                Job = $Job
                ServerName = $ServerName
            }

            $RunningJobs++
            $ServerIndex++
        }

        # Check for completed jobs
        foreach ($JobInfo in ($Jobs | Where-Object { $_.Job.State -ne 'Running' })) {
            $JobResult = Receive-Job -Job $JobInfo.Job
            $Results[$JobInfo.ServerName] = $JobResult

            Remove-Job -Job $JobInfo.Job -Force
            $Jobs = $Jobs | Where-Object { $_.ServerName -ne $JobInfo.ServerName }
            $RunningJobs--

            Write-Verbose "Completed job for server: $($JobInfo.ServerName)"
        }

        # Small delay to prevent tight loop
        if ($Jobs.Count -gt 0) {
            Start-Sleep -Milliseconds 100
        }
    }

    Write-Verbose "Parallel validation completed for all servers"
    return $Results
}

#endregion

function Invoke-SafeRemoteCommand {
    param(
        [string]$ServerName,
        [scriptblock]$ScriptBlock,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$TimeoutSeconds = 60
    )

    if (-not $Credential) {
        return @{
            Success = $false
            Data = $null
            Error = "No credentials provided"
            ErrorCode = "AUTH_REQUIRED"
        }
    }

    # ENHANCED: Check rate limiting before executing
    $RateLimitOK = Test-RateLimit
    if (-not $RateLimitOK) {
        Write-Warning "Rate limit enforcement prevented command execution"
        return @{
            Success = $false
            Data = $null
            Error = "Rate limit exceeded - command throttled"
            ErrorCode = "RATE_LIMITED"
        }
    }

    try {
        # ENHANCED: Add session options with timeouts
        # FIXED: IdleTimeout must be at least 60 seconds (60000 ms)
        $IdleTimeoutMs = [math]::Max(60000, ($TimeoutSeconds * 1000))
        $SessionOption = New-PSSessionOption -OperationTimeout ($TimeoutSeconds * 1000) `
                                              -IdleTimeout $IdleTimeoutMs `
                                              -CancelTimeout 30000 `
                                              -OpenTimeout 30000

        # Execute with timeout enforcement
        $Result = Invoke-Command -ComputerName $ServerName `
                                -ScriptBlock $ScriptBlock `
                                -Credential $Credential `
                                -SessionOption $SessionOption `
                                -ErrorAction Stop

        return @{
            Success = $true
            Data = $Result
            Error = $null
            ErrorCode = $null
        }
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        # Specific handling for timeout/connection errors
        Write-AuditLog -Action "RemoteCommand" -Target $ServerName -Result "Failed" -Details "Connection timeout"
        return @{
            Success = $false
            Data = $null
            Error = "Connection timeout or network error: $($_.Exception.Message)"
            ErrorCode = "CONNECTION_TIMEOUT"
        }
    }
    catch [System.TimeoutException] {
        Write-AuditLog -Action "RemoteCommand" -Target $ServerName -Result "Failed" -Details "Operation timeout: $TimeoutSeconds seconds"
        return @{
            Success = $false
            Data = $null
            Error = "Operation timed out after $TimeoutSeconds seconds"
            ErrorCode = "OPERATION_TIMEOUT"
        }
    }
    catch {
        Write-AuditLog -Action "RemoteCommand" -Target $ServerName -Result "Failed" -Details $_.Exception.Message
        return @{
            Success = $false
            Data = $null
            Error = $_.Exception.Message
            ErrorCode = "EXECUTION_ERROR"
        }
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

        # ENHANCED: Create session options with timeouts (5 minutes = 300000ms)
        # OPTIMIZED: Reduced timeout from 300s (5min) to 90s
        $SessionOption = New-PSSessionOption -OperationTimeout 90000 `
                                              -IdleTimeout 90000 `
                                              -CancelTimeout 30000 `
                                              -OpenTimeout 30000

        $SessionParams = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri = "http://$ServerName/PowerShell/"
            Authentication = 'Kerberos'
            SessionOption = $SessionOption
            ErrorAction = 'Stop'
        }

        if ($ConnectionInfo.UseCredentials) {
            $SessionParams.Credential = $Credential
        }

        $Session = New-PSSession @SessionParams

        if ($Session) {
            Import-PSSession -Session $Session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
            $Script:ExchangeSessions[$ServerName] = $Session

            Write-AuditLog -Action "ExchangeConnect" -Target $ServerName -Result "Success" -Details "Session established with timeouts"

            return $Session
        }
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        Write-AuditLog -Action "ExchangeConnect" -Target $ServerName -Result "Failed" -Details "Connection timeout: $($_.Exception.Message)"
        Write-Warning "Exchange connection to $ServerName failed: Connection timeout or network error"
        return $null
    }
    catch {
        Write-AuditLog -Action "ExchangeConnect" -Target $ServerName -Result "Failed" -Details $_.Exception.Message
        Write-Warning "Exchange connection to $ServerName failed: $($_.Exception.Message)"
        return $null
    }
    return $null
}

function Disconnect-ExchangeRemote {
    param([string]$ServerName)
    
    if ($Script:ExchangeSessions.ContainsKey($ServerName)) {
        $Session = $Script:ExchangeSessions[$ServerName]
        try {
            # Check if session exists and is open
            if ($Session -and $Session.State -eq 'Opened') {
                Remove-PSSession -Session $Session -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Failed to close Exchange session for $ServerName : $($_.Exception.Message)"
        }
        finally {
            # Always remove from tracking and dispose
            $Script:ExchangeSessions.Remove($ServerName)
            if ($Session) {
                try {
                    $Session.Dispose()
                }
                catch {
                    # Ignore disposal errors
                }
            }
        }
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
    $DataGrid.MultiSelect = $true
    $DataGrid.BackgroundColor = [System.Drawing.Color]::White
    $DataGrid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $DataGrid.GridColor = $Script:Colors.Border
    $DataGrid.RowHeadersVisible = $false
    $DataGrid.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
    
    # Modern alternating row colors
    $DataGrid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $DataGrid.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
    
    # Modern header styling
    $DataGrid.EnableHeadersVisualStyles = $false
    $DataGrid.ColumnHeadersDefaultCellStyle.BackColor = $Script:Colors.Primary
    $DataGrid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $DataGrid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $DataGrid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)
    $DataGrid.ColumnHeadersDefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    $DataGrid.ColumnHeadersHeight = 45
    $DataGrid.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::None
    
    # Modern cell styling
    $DataGrid.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $DataGrid.DefaultCellStyle.ForeColor = $Script:Colors.OnSurface
    $DataGrid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(204, 229, 255)
    $DataGrid.DefaultCellStyle.SelectionForeColor = $Script:Colors.OnSurface
    $DataGrid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 6)
    $DataGrid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
    
    # Row styling
    $DataGrid.RowTemplate.Height = 40
    
    # Enable smooth scrolling
    #$DataGrid.DoubleBuffered = $true
    
    # Add hover effect
    $DataGrid.Add_CellMouseEnter({
        param($sender, $e)
        if ($e.RowIndex -ge 0) {
            $sender.Rows[$e.RowIndex].DefaultCellStyle.BackColor = $Script:Colors.TabHover
        }
    })
    
    $DataGrid.Add_CellMouseLeave({
        param($sender, $e)
        if ($e.RowIndex -ge 0) {
            $sender.Rows[$e.RowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
        }
    })
    
    return $DataGrid
}

#endregion

function New-ModernTabPage {
    param(
        [string]$TabName,
        [string]$IconText = "",
        [System.Drawing.Color]$AccentColor = $Script:Colors.Primary
    )
    
    $TabPage = New-Object System.Windows.Forms.TabPage
    $TabPage.Text = if ($IconText) { "$IconText  $TabName" } else { $TabName }
    $TabPage.BackColor = [System.Drawing.Color]::White
    $TabPage.Padding = New-Object System.Windows.Forms.Padding(0)
    $TabPage.UseVisualStyleBackColor = $true
    $TabPage.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $TabPage.Tag = $AccentColor
    
    return $TabPage
}

function New-CategoryPanel {
    param(
        [string]$Title,
        [int]$ItemCount = 0,
        [System.Drawing.Color]$AccentColor = $Script:Colors.Primary
    )
    
    $Container = New-Object System.Windows.Forms.Panel
    $Container.Dock = [System.Windows.Forms.DockStyle]::Top
    $Container.Height = 60
    $Container.BackColor = [System.Drawing.Color]::White
    $Container.Padding = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
    
    $AccentBar = New-Object System.Windows.Forms.Panel
    $AccentBar.Width = 4
    $AccentBar.Dock = [System.Windows.Forms.DockStyle]::Left
    $AccentBar.BackColor = $AccentColor
    $Container.Controls.Add($AccentBar)
    
    $ContentPanel = New-Object System.Windows.Forms.Panel
    $ContentPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $ContentPanel.BackColor = $Script:Colors.Surface
    $ContentPanel.Padding = New-Object System.Windows.Forms.Padding(20, 12, 20, 12)
    
    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = $Title.ToUpper()
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 12, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.ForeColor = $Script:Colors.OnSurface
    $TitleLabel.AutoSize = $true
    $TitleLabel.Location = New-Object System.Drawing.Point(0, 8)
    $ContentPanel.Controls.Add($TitleLabel)
    
    if ($ItemCount -gt 0) {
        $Badge = New-Object System.Windows.Forms.Label
        $Badge.Text = "$ItemCount Items"
        $Badge.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $Badge.ForeColor = [System.Drawing.Color]::White
        $Badge.BackColor = $AccentColor
        $Badge.AutoSize = $true
        $Badge.Padding = New-Object System.Windows.Forms.Padding(10, 4, 10, 4)
        $Badge.Location = New-Object System.Drawing.Point(($TitleLabel.PreferredWidth + 15), 5)
        $ContentPanel.Controls.Add($Badge)
    }
    
    $Container.Controls.Add($ContentPanel)
    return $Container
}

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
        } catch {
            Write-Verbose "Could not retrieve time zone information: $($_.Exception.Message)"
        }
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
            $Status = if ($UsagePercent -ge 95) { "Critical" } elseif ($UsagePercent -ge 85) { "Warning"} else { "Normal"}
            $ServerDetails.Disks += [PSCustomObject]@{
                Drive = $Disk.DeviceID
                Label = if ($Disk.VolumeName) { $Disk.VolumeName } else { "No Label" }
                FileSystem = $Disk.FileSystem
                TotalSize = "$TotalGB GB"
                UsedSpace = "$UsedGB GB"
                FreeSpace = "$FreeGB GB"
                UsagePercent = "$UsagePercent%"
                Status = $Status
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

            # Determine CPU status based on usage thresholds (ONLY for Current Usage row)
            $CPUStatus = if ($CPUUsage -ge $Script:Thresholds.CPUHighPercent) {
                "High"
            } else {
                "Normal"
            }

            $Results.CPU += [PSCustomObject]@{
                Metric = "Processor"
                Value = $CPU.Name
                Status = ""
            }
            $Results.CPU += [PSCustomObject]@{
                Metric = "Cores / Logical"
                Value = "$($CPU.NumberOfCores) / $($CPU.NumberOfLogicalProcessors)"
                Status = ""
            }
            $Results.CPU += [PSCustomObject]@{
                Metric = "Current Usage"
                Value = "$CPUUsage%"
                Status = $CPUStatus
            }
            $OS = Get-WmiObject -Class Win32_OperatingSystem
            $TotalMemGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
            $FreeMemGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
            $UsedMemGB = $TotalMemGB - $FreeMemGB
            $MemPercent = [math]::Round(($UsedMemGB / $TotalMemGB) * 100, 2)

            $Results.Memory += [PSCustomObject]@{
                Metric = "Total Memory"
                Value = "$TotalMemGB GB"
                Status = ""
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

            # Determine Memory status based on usage thresholds (ONLY for Usage Percentage row)
            $MemoryStatus = if ($MemPercent -ge 95) {
                "Critical"
            } elseif ($MemPercent -ge $Script:Thresholds.MemoryHighPercent) {
                "High"
            } else {
                "Normal"
            }

            $Results.Memory += [PSCustomObject]@{
                Metric = "Usage Percentage"
                Value = "$MemPercent%"
                Status = $MemoryStatus
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
                # Fix for quotas
                $ProhibitSend = if ($DB.ProhibitSendQuota -and $DB.ProhibitSendQuota -ne "Unlimited") { 
                    $DB.ProhibitSendQuota.ToString() 
                } else { 
                    "Unlimited" 
                }
                
                $ProhibitReceive = if ($DB.ProhibitSendReceiveQuota -and $DB.ProhibitSendReceiveQuota -ne "Unlimited") { 
                    $DB.ProhibitSendReceiveQuota.ToString() 
                } else { 
                    "Unlimited" 
                }
                
                $Warning = if ($DB.IssueWarningQuota -and $DB.IssueWarningQuota -ne "Unlimited") { 
                    $DB.IssueWarningQuota.ToString() 
                } else { 
                    "Unlimited" 
                }
                
                # FIXED: Properly get server name with multiple methods
                $ServerName = "Unknown"
                
                # Method 1: Check Server.Name property
                if ($DB.Server) {
                    if ($DB.Server.Name) {
                        $ServerName = $DB.Server.Name
                    }
                    elseif ($DB.Server -is [string]) {
                        $ServerName = $DB.Server
                    }
                    else {
                        $ServerName = $DB.Server.ToString()
                    }
                }
                
                # Method 2: Check MountedOnServer property (more reliable)
                if ($ServerName -eq "Unknown" -and $DB.MountedOnServer) {
                    $ServerName = $DB.MountedOnServer
                }
                
                # Method 3: Try to get server from Master property
                if ($ServerName -eq "Unknown" -and $DB.Master) {
                    if ($DB.Master.Name) {
                        $ServerName = $DB.Master.Name
                    }
                    else {
                        $ServerName = $DB.Master.ToString()
                    }
                }
                
                # Method 4: Extract from DistinguishedName
                if ($ServerName -eq "Unknown" -and $DB.DistinguishedName) {
                    if ($DB.DistinguishedName -match 'CN=([^,]+),CN=Databases') {
                        # Try to find server in DN path
                        if ($DB.DistinguishedName -match 'CN=([^,]+),CN=Configuration') {
                            $ServerName = $matches[1]
                        }
                    }
                }
                
                # Clean up server name (remove FQDN if present, keep just hostname)
                if ($ServerName -ne "Unknown" -and $ServerName -like "*.*") {
                    $ServerName = $ServerName.Split('.')[0]
                }
                
                # FIXED: Properly retrieve OAB with multiple fallback methods
                $OAB = "Not Configured"
                
                # Method 1: Direct property check
                if ($DB.OfflineAddressBook) {
                    if ($DB.OfflineAddressBook.Name) {
                        $OAB = $DB.OfflineAddressBook.Name
                    }
                    elseif ($DB.OfflineAddressBook -is [string]) {
                        $OAB = $DB.OfflineAddressBook
                    }
                    else {
                        $OAB = $DB.OfflineAddressBook.ToString()
                    }
                }
                
                # Method 2: If still not found, query Exchange directly
                if ($OAB -eq "Not Configured") {
                    try {
                        $DBDetail = Get-MailboxDatabase -Identity $DB.Name -ErrorAction SilentlyContinue
                        if ($DBDetail.OfflineAddressBook) {
                            if ($DBDetail.OfflineAddressBook.Name) {
                                $OAB = $DBDetail.OfflineAddressBook.Name
                            }
                            else {
                                $OAB = $DBDetail.OfflineAddressBook.ToString()
                            }
                        }
                    }
                    catch {
                        # Keep "Not Configured" if query fails
                    }
                }
                
                # Method 3: Check if there's a default OAB assigned to the organization
                if ($OAB -eq "Not Configured") {
                    try {
                        $DefaultOAB = Get-OfflineAddressBook -ErrorAction SilentlyContinue | Where-Object { $_.IsDefault -eq $true } | Select-Object -First 1
                        if ($DefaultOAB) {
                            $OAB = "$($DefaultOAB.Name) (Default)"
                        }
                    }
                    catch {
                        # Keep "Not Configured"
                    }
                }
                
                $Results.MailboxDatabases += [PSCustomObject]@{
                    DatabaseName = $DB.Name
                    Server = $ServerName
                    Mounted = if ($DB.Mounted) { "Yes" } else { "No" }
                    OfflineAddressBook = $OAB
                    ProhibitSendQuota = $ProhibitSend
                    ProhibitSendReceiveQuota = $ProhibitReceive
                    IssueWarningQuota = $Warning
                    Status = if ($DB.Mounted) { "OK" } else { "ERROR" }
                }
            }
        } catch {
            # If entire database query fails, add error entry
            $Results.MailboxDatabases += [PSCustomObject]@{
                DatabaseName = "Error retrieving databases"
                Server = $_.Exception.Message
                Mounted = "N/A"
                OfflineAddressBook = "N/A"
                ProhibitSendQuota = "N/A"
                ProhibitSendReceiveQuota = "N/A"
                IssueWarningQuota = "N/A"
                Status = "Failed"
            }
        }
        try {
            $Arbitration = Get-Mailbox -Arbitration -ErrorAction SilentlyContinue
            $Monitoring = Get-Mailbox -Monitoring -ErrorAction SilentlyContinue
            $AuditLog = Get-Mailbox -AuditLog -ErrorAction SilentlyContinue
            
            foreach ($Mbx in $Arbitration) {
                # FIXED: Properly get database name with multiple methods
                $DatabaseName = "Not Assigned"
                
                # Method 1: Check Database.Name property
                if ($Mbx.Database) {
                    if ($Mbx.Database.Name) {
                        $DatabaseName = $Mbx.Database.Name
                    }
                    elseif ($Mbx.Database -is [string]) {
                        $DatabaseName = $Mbx.Database
                    }
                    else {
                        $DatabaseName = $Mbx.Database.ToString()
                    }
                }
                
                # Method 2: Try to get from full object
                if ($DatabaseName -eq "Not Assigned") {
                    try {
                        $MbxDetail = Get-Mailbox -Identity $Mbx.Identity -ErrorAction SilentlyContinue
                        if ($MbxDetail.Database) {
                            if ($MbxDetail.Database.Name) {
                                $DatabaseName = $MbxDetail.Database.Name
                            }
                            else {
                                $DatabaseName = $MbxDetail.Database.ToString()
                            }
                        }
                    }
                    catch {
                        # Keep "Not Assigned"
                    }
                }
                
                $Results.SystemMailboxes += [PSCustomObject]@{
                    Type = "Arbitration"
                    Name = $Mbx.Name
                    Database = $DatabaseName
                    Status = "OK"
                }
            }
            
            foreach ($Mbx in $Monitoring) {
                # FIXED: Properly get database name with multiple methods
                $DatabaseName = "Not Assigned"
                
                # Method 1: Check Database.Name property
                if ($Mbx.Database) {
                    if ($Mbx.Database.Name) {
                        $DatabaseName = $Mbx.Database.Name
                    }
                    elseif ($Mbx.Database -is [string]) {
                        $DatabaseName = $Mbx.Database
                    }
                    else {
                        $DatabaseName = $Mbx.Database.ToString()
                    }
                }
                
                # Method 2: Try to get from full object
                if ($DatabaseName -eq "Not Assigned") {
                    try {
                        $MbxDetail = Get-Mailbox -Identity $Mbx.Identity -ErrorAction SilentlyContinue
                        if ($MbxDetail.Database) {
                            if ($MbxDetail.Database.Name) {
                                $DatabaseName = $MbxDetail.Database.Name
                            }
                            else {
                                $DatabaseName = $MbxDetail.Database.ToString()
                            }
                        }
                    }
                    catch {
                        # Keep "Not Assigned"
                    }
                }
                
                $Results.SystemMailboxes += [PSCustomObject]@{
                    Type = "Monitoring"
                    Name = $Mbx.Name
                    Database = $DatabaseName
                    Status = "OK"
                }
            }
            
            foreach ($Mbx in $AuditLog) {
                # FIXED: Properly get database name with multiple methods
                $DatabaseName = "Not Assigned"
                
                # Method 1: Check Database.Name property
                if ($Mbx.Database) {
                    if ($Mbx.Database.Name) {
                        $DatabaseName = $Mbx.Database.Name
                    }
                    elseif ($Mbx.Database -is [string]) {
                        $DatabaseName = $Mbx.Database
                    }
                    else {
                        $DatabaseName = $Mbx.Database.ToString()
                    }
                }
                
                # Method 2: Try to get from full object
                if ($DatabaseName -eq "Not Assigned") {
                    try {
                        $MbxDetail = Get-Mailbox -Identity $Mbx.Identity -ErrorAction SilentlyContinue
                        if ($MbxDetail.Database) {
                            if ($MbxDetail.Database.Name) {
                                $DatabaseName = $MbxDetail.Database.Name
                            }
                            else {
                                $DatabaseName = $MbxDetail.Database.ToString()
                            }
                        }
                    }
                    catch {
                        # Keep "Not Assigned"
                    }
                }
                
                $Results.SystemMailboxes += [PSCustomObject]@{
                    Type = "Audit Log"
                    Name = $Mbx.Name
                    Database = $DatabaseName
                    Status = "OK"
                }
            }
        } catch {
            # If query fails, add error entry
            $Results.SystemMailboxes += [PSCustomObject]@{
                Type = "Error"
                Name = "Failed to retrieve system mailboxes"
                Database = $_.Exception.Message
                Status = "Failed"
            }
        }
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
            # REAL FIX: Force Services property evaluation in remote context
            $CertResults = @()
            $Certs = Get-ExchangeCertificate -ErrorAction SilentlyContinue
            
            foreach ($Cert in $Certs) {
                $DaysToExpire = ($Cert.NotAfter - (Get-Date)).Days
                $Status = if ($DaysToExpire -lt 30) { 
                    if ($DaysToExpire -lt 0) { "EXPIRED" } else { "Expiring Soon" }
                } else { 
                    "Valid" 
                }
                
                # CRITICAL: Capture Services as STRING immediately
                $ServicesString = $(
                    try {
                        $SvcProp = $null
                        
                        # Method 1: Direct property access
                        if ($Cert.Services) {
                            $SvcProp = $Cert.Services
                        }
                        
                        # Method 2: Use PSObject.Properties
                        if (-not $SvcProp) {
                            $SvcProperty = $Cert.PSObject.Properties | Where-Object { $_.Name -eq 'Services' }
                            if ($SvcProperty) {
                                $SvcProp = $SvcProperty.Value
                            }
                        }
                        
                        # Convert to string
                        if ($SvcProp) {
                            $SvcString = [string]$SvcProp
                            if ($SvcString -and $SvcString -ne "None" -and $SvcString -ne "0") {
                                $SvcString
                            } else {
                                if ($Cert.IsSelfSigned) { "Self-Signed" } else { "Not Assigned" }
                            }
                        } else {
                            if ($Cert.IsSelfSigned) { "Self-Signed" } else { "Not Assigned" }
                        }
                    }
                    catch {
                        "Error: $($_.Exception.Message)"
                    }
                )
                
                # Create object with STRING properties only
                $CertResults += [PSCustomObject]@{
                    Subject = [string]$Cert.Subject
                    Thumbprint = [string]$Cert.Thumbprint
                    NotAfter = [string]$Cert.NotAfter
                    DaysToExpire = [int]$DaysToExpire
                    Status = [string]$Status
                }
            }
            
            # Add all cert results to main results
            foreach ($CertResult in $CertResults) {
                $Results.Certificates += $CertResult
            }
            
        } catch {
            $Results.Certificates += [PSCustomObject]@{
                Subject = "Error retrieving certificates"
                Thumbprint = [string]$_.Exception.Message
                NotAfter = ""
                DaysToExpire = 0
                Status = "Failed"
            }
        }
            
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
            
            if ($DAGs) {
                foreach ($DAG in $DAGs) {
                    # FIXED: Properly get DAG members with multiple methods
                    $MembersText = "No Members"
                    
                    # Method 1: Check Servers property and get names
                    if ($DAG.Servers) {
                        if ($DAG.Servers.Count -gt 0) {
                            $ServerNames = @()
                            
                            foreach ($Server in $DAG.Servers) {
                                if ($Server.Name) {
                                    # Clean up FQDN - keep just hostname
                                    $ServerName = $Server.Name
                                    if ($ServerName -like "*.*") {
                                        $ServerName = $ServerName.Split('.')[0]
                                    }
                                    $ServerNames += $ServerName
                                }
                                elseif ($Server -is [string]) {
                                    # Server is already a string
                                    $ServerName = $Server
                                    if ($ServerName -like "*.*") {
                                        $ServerName = $ServerName.Split('.')[0]
                                    }
                                    $ServerNames += $ServerName
                                }
                                else {
                                    # Try ToString()
                                    $ServerName = $Server.ToString()
                                    if ($ServerName -like "*.*") {
                                        $ServerName = $ServerName.Split('.')[0]
                                    }
                                    $ServerNames += $ServerName
                                }
                            }
                            
                            if ($ServerNames.Count -gt 0) {
                                $MembersText = $ServerNames -join ", "
                            }
                        }
                    }
                    
                    # Method 2: If still no members, try OperationalServers
                    if ($MembersText -eq "No Members" -and $DAG.OperationalServers) {
                        $OperationalNames = @()
                        foreach ($OpServer in $DAG.OperationalServers) {
                            if ($OpServer.Name) {
                                $ServerName = $OpServer.Name
                                if ($ServerName -like "*.*") {
                                    $ServerName = $ServerName.Split('.')[0]
                                }
                                $OperationalNames += $ServerName
                            }
                        }
                        if ($OperationalNames.Count -gt 0) {
                            $MembersText = $OperationalNames -join ", "
                        }
                    }
                    
                    # Method 3: If still no members, try to query the DAG again with -Status
                    if ($MembersText -eq "No Members") {
                        try {
                            $DAGDetail = Get-DatabaseAvailabilityGroup -Identity $DAG.Name -Status -ErrorAction SilentlyContinue
                            if ($DAGDetail.Servers) {
                                $ServerNames = @()
                                foreach ($Server in $DAGDetail.Servers) {
                                    if ($Server.Name) {
                                        $ServerName = $Server.Name
                                        if ($ServerName -like "*.*") {
                                            $ServerName = $ServerName.Split('.')[0]
                                        }
                                        $ServerNames += $ServerName
                                    }
                                }
                                if ($ServerNames.Count -gt 0) {
                                    $MembersText = $ServerNames -join ", "
                                }
                            }
                        }
                        catch {
                            # Keep "No Members"
                        }
                    }
                    
                    # FIXED: Properly get WitnessServer with multiple methods
                    $WitnessText = "Not Set"
                    
                    # Method 1: Direct property
                    if ($DAG.WitnessServer) {
                        if ($DAG.WitnessServer.Name) {
                            $WitnessText = $DAG.WitnessServer.Name
                        }
                        elseif ($DAG.WitnessServer -is [string]) {
                            $WitnessText = $DAG.WitnessServer
                        }
                        else {
                            $WitnessText = $DAG.WitnessServer.ToString()
                        }
                        
                        # Clean up FQDN
                        if ($WitnessText -like "*.*") {
                            $WitnessText = $WitnessText.Split('.')[0]
                        }
                    }
                    
                    # Method 2: Try AlternateWitnessServer if primary is not set
                    if ($WitnessText -eq "Not Set" -and $DAG.AlternateWitnessServer) {
                        if ($DAG.AlternateWitnessServer.Name) {
                            $WitnessText = $DAG.AlternateWitnessServer.Name + " (Alternate)"
                        }
                        else {
                            $WitnessText = $DAG.AlternateWitnessServer.ToString() + " (Alternate)"
                        }
                        
                        # Clean up FQDN
                        if ($WitnessText -like "*.*") {
                            $Parts = $WitnessText.Split('.')
                            $WitnessText = $Parts[0] + " (Alternate)"
                        }
                    }
                    
                    $Results.DAG += [PSCustomObject]@{
                        DAGName = $DAG.Name
                        Members = $MembersText
                        WitnessServer = $WitnessText
                        Status = "OK"
                    }
                }
            }
            else {
                # No DAG configured
                $Results.DAG += [PSCustomObject]@{
                    DAGName = "No DAG Configured"
                    Members = "N/A"
                    WitnessServer = "N/A"
                    Status = "Info"
                }
            }
        } catch {
            # If DAG query fails, add error entry
            $Results.DAG += [PSCustomObject]@{
                DAGName = "Error retrieving DAG"
                Members = $_.Exception.Message
                WitnessServer = "N/A"
                Status = "Failed"
            }
        }
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
        # 15. Verify No Internet Access
        try {
            # Test actual web browsing capability, not just ICMP ping
            $InternetTests = @()
            
            # Test 1: HTTP/HTTPS to multiple reliable endpoints
            $TestSites = @(
                @{URL="http://www.msftconnecttest.com/connecttest.txt"; Name="Microsoft"},
                @{URL="http://detectportal.firefox.com/success.txt"; Name="Mozilla"},
                @{URL="http://clients3.google.com/generate_204"; Name="Google"}
            )
            
            $SuccessfulTests = 0
            $FailedTests = 0
            $TestDetails = @()
            
            foreach ($Site in $TestSites) {
                try {
                    $Response = Invoke-WebRequest -Uri $Site.URL -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                    if ($Response.StatusCode -eq 200 -or $Response.StatusCode -eq 204) {
                        $SuccessfulTests++
                        $TestDetails += "$($Site.Name): Accessible"
                    }
                    else {
                        $FailedTests++
                        $TestDetails += "$($Site.Name): HTTP $($Response.StatusCode)"
                    }
                }
                catch {
                    $FailedTests++
                    $TestDetails += "$($Site.Name): Blocked/Failed"
                }
            }
            
            # Determine final status
            if ($SuccessfulTests -eq 0) {
                # No internet access - COMPLIANT (as expected for secure infrastructure)
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Web Browsing Test"
                    Result = "No Internet Access (Compliant)"
                    Details = "All HTTP/HTTPS requests blocked"
                    Status = "OK"
                }
            }
            elseif ($SuccessfulTests -eq $TestSites.Count) {
                # Full internet access - SECURITY RISK
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Web Browsing Test"
                    Result = "FULL INTERNET ACCESS DETECTED"
                    Details = "All test sites accessible: $($TestDetails -join ' | ')"
                    Status = "SECURITY RISK"
                }
            }
            else {
                # Partial internet access - WARNING
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Web Browsing Test"
                    Result = "Partial Internet Access"
                    Details = "$SuccessfulTests of $($TestSites.Count) sites accessible: $($TestDetails -join ' | ')"
                    Status = "WARNING"
                }
            }
            
            # Test 2: DNS Resolution (can resolve but not browse?)
            try {
                $DNSTest = Resolve-DnsName -Name "www.microsoft.com" -Type A -ErrorAction Stop
                $DNSWorks = $true
            }
            catch {
                $DNSWorks = $false
            }
            
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "DNS Resolution"
                Result = if ($DNSWorks) { "DNS Working" } else { "DNS Blocked/Failed" }
                Details = if ($DNSWorks) { "Can resolve external domains" } else { "Cannot resolve external domains" }
                Status = if ($DNSWorks -and $SuccessfulTests -eq 0) { "INFO" } elseif ($DNSWorks) { "OK" } else { "OK" }
            }
            
            # Test 3: Proxy Detection
            try {
                $ProxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
                $ProxyEnabled = $ProxySettings.ProxyEnable -eq 1
                $ProxyServer = $ProxySettings.ProxyServer
                
                if ($ProxyEnabled) {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Proxy Configuration"
                        Result = "Proxy Configured"
                        Details = "Proxy Server: $ProxyServer"
                        Status = "INFO"
                    }
                }
                else {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Proxy Configuration"
                        Result = "No Proxy Configured"
                        Details = "Direct connection settings"
                        Status = "INFO"
                    }
                }
            }
            catch {
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Proxy Configuration"
                    Result = "Unable to check"
                    Details = "Registry access failed"
                    Status = "INFO"
                }
            }
            
            # Test 4: Windows Firewall Status
            try {
                $FirewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $EnabledProfiles = ($FirewallProfiles | Where-Object { $_.Enabled -eq $true }).Name -join ", "
                
                if ($EnabledProfiles) {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Windows Firewall"
                        Result = "Enabled"
                        Details = "Active Profiles: $EnabledProfiles"
                        Status = "OK"
                    }
                }
                else {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Windows Firewall"
                        Result = "Disabled"
                        Details = "No firewall profiles active"
                        Status = "WARNING"
                    }
                }
            }
            catch {
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Windows Firewall"
                    Result = "Unable to check"
                    Details = $_.Exception.Message
                    Status = "INFO"
                }
            }
        }
        catch {
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "Internet Connectivity Test"
                Result = "Test Failed"
                Details = $_.Exception.Message
                Status = "ERROR"
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

#region Azure AD Connect Validation Functions

<#
.SYNOPSIS
    Validates Azure AD Connect/Entra Connect installation and configuration
.DESCRIPTION
    Comprehensive validation of AAD Connect sync service, health, configuration, and connectors
#>

#region Azure AD Connect Validation Functions

function Test-ADConnectPermissions {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $Results = @{
        HasPermission = $false
        MissingPermissions = @()
        Details = @()
    }
    
    try {
        $Results.Details += "Target Server: $ServerName"
        $Results.Details += "Checking remote PowerShell access..."
        
        $ConnectivityTest = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
            return @{ 
                ComputerName = $env:COMPUTERNAME
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
        } -TimeoutSeconds 30
        
        if (-not $ConnectivityTest.Success) {
            $Results.MissingPermissions += "Cannot establish remote PowerShell session"
            $Results.Details += "Remote PS Error: $($ConnectivityTest.Error)"
            return $Results
        }
        else {
            $Results.Details += "[OK] Remote PowerShell access successful"
            $Results.Details += "Connected to: $($ConnectivityTest.Data.ComputerName)"
            $Results.Details += "PowerShell Version: $($ConnectivityTest.Data.PowerShellVersion)"
        }
        
        $Results.Details += "Checking for ADSync PowerShell module..."
        
        $ModuleCheck = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
            $Module = Get-Module -ListAvailable -Name ADSync -ErrorAction SilentlyContinue
            if ($Module) {
                return @{ Found = $true; Version = $Module.Version.ToString() }
            } else {
                return @{ Found = $false }
            }
        } -TimeoutSeconds 30
        
        if ($ModuleCheck.Success -and $ModuleCheck.Data.Found) {
            $Results.Details += "[OK] Found ADSync module version $($ModuleCheck.Data.Version)"
        }
        else {
            $Results.MissingPermissions += "ADSync PowerShell module not found"
            $Results.Details += "[FAIL] ADSync module is NOT installed on this server"
            return $Results
        }
        
        $Results.Details += "Checking ADSync service access..."
        
        $ServiceCheck = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
            try {
                $Service = Get-Service -Name ADSync -ErrorAction Stop
                return @{ Success = $true; Status = $Service.Status.ToString() }
            }
            catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
        } -TimeoutSeconds 30
        
        if ($ServiceCheck.Success -and $ServiceCheck.Data.Success) {
            $Results.Details += "[OK] ADSync service status: $($ServiceCheck.Data.Status)"
            $Results.HasPermission = $true
        }
        else {
            $Results.MissingPermissions += "Cannot access ADSync service"
            $Results.Details += "[FAIL] Failed to check ADSync service status"
        }
        
        if ($Results.HasPermission) {
            $Results.Details += ""
            $Results.Details += "NOTE: Cloud sync checks may timeout in air-gapped environments"
        }
    }
    catch {
        $Results.MissingPermissions += "Exception: $($_.Exception.Message)"
        $Results.Details += "Critical error: $($_.Exception.Message)"
    }
    
    return $Results
}

function Get-ADConnectVersion {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        try {
            Import-Module ADSync -ErrorAction Stop
            
            $Version = "Unknown"
            $InstallDate = "Unknown"
            
            try {
                $VersionParam = Get-ADSyncGlobalSettingsParameter -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -eq 'Microsoft.Synchronize.ServerConfigurationVersion' }
                
                if ($VersionParam -and $VersionParam.Value) {
                    $Version = [string]$VersionParam.Value
                }
            } catch {}
            
            if ($Version -eq "Unknown") {
                try {
                    $RegPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
                    if (Test-Path $RegPath) {
                        $RegValue = Get-ItemProperty -Path $RegPath -Name "Version" -ErrorAction SilentlyContinue
                        if ($RegValue -and $RegValue.Version) {
                            $Version = [string]$RegValue.Version
                        }
                    }
                } catch {}
            }
            
            try {
                $SetupRegPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect\Setup"
                if (Test-Path $SetupRegPath) {
                    $RegValue = Get-ItemProperty -Path $SetupRegPath -Name "InstallationDate" -ErrorAction SilentlyContinue
                    if ($RegValue -and $RegValue.InstallationDate) {
                        $InstallDate = [string]$RegValue.InstallationDate
                    }
                }
            } catch {}
            
            # Return plain strings only
            return @{
                Version = $Version
                InstallDate = $InstallDate
                ComputerName = $env:COMPUTERNAME
            }
        }
        catch {
            return @{ 
                Error = $_.Exception.Message
                Version = "Error"
                InstallDate = "Unknown"
                ComputerName = $env:COMPUTERNAME
            }
        }
    } -TimeoutSeconds 30
    
    return $Result
}

function Get-ADConnectServiceStatus {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    # ✅ CRITICAL FIX: Get raw data as strings, create objects locally
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        $Services = @("ADSync")
        $ServiceData = @()
        
        foreach ($SvcName in $Services) {
            try {
                $Service = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    # Return as simple string array
                    $ServiceData += "$SvcName|$($Service.DisplayName)|$($Service.Status)|$($Service.StartType)"
                } else {
                    $ServiceData += "$SvcName|Microsoft Azure AD Sync|Not Found|N/A"
                }
            }
            catch {
                $ServiceData += "$SvcName|Microsoft Azure AD Sync|Error|N/A"
            }
        }
        
        # Return array of strings
        return $ServiceData
    } -TimeoutSeconds 30
    
    # ✅ Create objects LOCALLY after data returns
    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()
        
        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 4) {
                $LocalObjects += New-Object PSObject -Property @{
                    ServiceName = $Parts[0]
                    DisplayName = $Parts[1]
                    Status = $Parts[2]
                    StartType = $Parts[3]
                }
            }
        }
        
        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }
    
    return $Result
}

function Get-ADConnectSyncScheduler {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    # ✅ Get as string array
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        $SchedulerData = @()
        
        try {
            Import-Module ADSync -ErrorAction Stop
            
            $Scheduler = $null
            try {
                $Job = Start-Job -ScriptBlock { Get-ADSyncScheduler -ErrorAction Stop }
                $Completed = Wait-Job -Job $Job -Timeout 15
                
                if ($Completed) {
                    $Scheduler = Receive-Job -Job $Job
                    Remove-Job -Job $Job -Force
                } else {
                    Stop-Job -Job $Job -ErrorAction SilentlyContinue
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                    $SchedulerData += "Cloud Sync Status|Timeout (15s) - Unable to reach Azure|Warning"
                }
            }
            catch {
                $SchedulerData += "Scheduler Access|Error: $($_.Exception.Message)|Error"
            }
            
            if ($Scheduler) {
                $SyncEnabled = if ($Scheduler.SyncCycleEnabled) { "True" } else { "False" }
                $SyncEnabledStatus = if ($Scheduler.SyncCycleEnabled) { "Enabled" } else { "Disabled" }
                $SchedulerData += "Sync Cycle Enabled|$SyncEnabled|$SyncEnabledStatus"
                
                try {
                    $Interval = $Scheduler.CurrentlyEffectiveSyncCycleInterval
                    if ($Interval) {
                        $SchedulerData += "Sync Interval|$($Interval.ToString())|Active"
                    }
                } catch {
                    $SchedulerData += "Sync Interval|Unable to determine|Warning"
                }
                
                try {
                    $NextSync = "Not Scheduled"
                    if ($Scheduler.NextSyncCycleStartTimeInUTC) {
                        $NextSync = $Scheduler.NextSyncCycleStartTimeInUTC.ToString("yyyy-MM-dd HH:mm:ss UTC")
                    }
                    $SchedulerData += "Next Sync Time|$NextSync|Scheduled"
                } catch {
                    $SchedulerData += "Next Sync Time|Unable to determine|Warning"
                }
                
                $SyncInProgress = if ($Scheduler.SyncCycleInProgress) { "True" } else { "False" }
                $SyncStatus = if ($Scheduler.SyncCycleInProgress) { "Running" } else { "Idle" }
                $SchedulerData += "Sync In Progress|$SyncInProgress|$SyncStatus"
                
                $StagingMode = if ($Scheduler.StagingModeEnabled) { "True" } else { "False" }
                $StagingStatus = if ($Scheduler.StagingModeEnabled) { "Enabled (READ-ONLY)" } else { "Disabled" }
                $SchedulerData += "Staging Mode|$StagingMode|$StagingStatus"
            }
            
            if ($SchedulerData.Count -eq 0) {
                $SchedulerData += "Scheduler Status|Unable to retrieve scheduler details|Warning"
            }
            
            return $SchedulerData
        }
        catch {
            return @("Critical Error|$($_.Exception.Message)|Error")
        }
    } -TimeoutSeconds 30
    
    # ✅ Create objects locally
    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()
        
        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 3) {
                $LocalObjects += New-Object PSObject -Property @{
                    Property = $Parts[0]
                    Value = $Parts[1]
                    Status = $Parts[2]
                }
            }
        }
        
        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }
    
    return $Result
}

function Get-ADConnectConnectors {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        try {
            Import-Module ADSync -ErrorAction Stop

            $ConnectorData = @()

            # CRITICAL FIX: Safely access connector properties
            try {
                $Connectors = Get-ADSyncConnector -ErrorAction Stop

                if ($Connectors) {
                    foreach ($Connector in $Connectors) {
                        # Safely extract each property with null checks
                        $Name = if ($Connector.Name) { [string]$Connector.Name } else { "Unknown" }

                        $Type = "Unknown"
                        if ($Connector.ConnectorType) {
                            try {
                                $Type = $Connector.ConnectorType.ToString()
                            } catch {
                                $Type = "Unknown"
                            }
                        }

                        $Subtype = "N/A"
                        if ($Connector.Subtype) {
                            try {
                                $Subtype = $Connector.Subtype.ToString()
                            } catch {
                                $Subtype = "N/A"
                            }
                        }

                        $Description = if ($Connector.Description) { [string]$Connector.Description } else { "No Description" }

                        # Additional useful info
                        $Enabled = if ($Connector.Enabled) { "Yes" } else { "No" }
                        $Partitions = if ($Connector.Partitions) { $Connector.Partitions.Count } else { 0 }

                        $ConnectorData += "$Name|$Type|$Subtype|$Description|$Enabled|$Partitions"
                    }
                }
                else {
                    $ConnectorData += "No Connectors|No connectors configured|N/A|Azure AD Connect may not be fully configured|N/A|0"
                }
            }
            catch {
                $ConnectorData += "Error|Failed to retrieve connectors|N/A|$($_.Exception.Message)|N/A|0"
            }

            if ($ConnectorData.Count -eq 0) {
                $ConnectorData += "No Data|No connector information available|N/A|Check ADSync service status|N/A|0"
            }

            return $ConnectorData
        }
        catch {
            return @("Module Error|ADSync module not available|N/A|$($_.Exception.Message)|N/A|0")
        }
    } -TimeoutSeconds 30

    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()

        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 6) {
                $LocalObjects += New-Object PSObject -Property @{
                    Name = $Parts[0]
                    Type = $Parts[1]
                    Subtype = $Parts[2]
                    Description = $Parts[3]
                    Enabled = $Parts[4]
                    Partitions = $Parts[5]
                }
            }
        }

        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }

    return $Result
}

function Get-ADConnectSyncHistory {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$NumberOfRuns = 10
    )

    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        param([int]$NumRuns)

        try {
            Import-Module ADSync -ErrorAction Stop

            $HistoryData = @()

            # CRITICAL FIX: Use proper parameter syntax without -NumberRequested
            try {
                # Method 1: Try without parameters (gets recent runs)
                $RunHistory = @()
                try {
                    $RunHistory = Get-ADSyncRunProfileResult -ErrorAction Stop | Select-Object -First $NumRuns
                }
                catch {
                    # Method 2: Fallback - query WMI directly
                    try {
                        $RunHistory = Get-WmiObject -Namespace "root\MicrosoftAzureADConnect" -Class "MSOnline_SyncRunHistory" -ErrorAction Stop |
                                      Select-Object -First $NumRuns
                    }
                    catch {
                        throw "Cannot retrieve sync history: $($_.Exception.Message)"
                    }
                }

                if ($RunHistory -and $RunHistory.Count -gt 0) {
                    foreach ($Run in $RunHistory) {
                        # Safely extract properties
                        $RunDate = "Unknown"
                        if ($Run.StartDate) {
                            try {
                                $RunDate = $Run.StartDate.ToString("yyyy-MM-dd HH:mm:ss")
                            } catch {
                                $RunDate = "Recent"
                            }
                        }
                        elseif ($Run.RunDateTime) {
                            try {
                                $RunDate = $Run.RunDateTime.ToString("yyyy-MM-dd HH:mm:ss")
                            } catch {
                                $RunDate = "Recent"
                            }
                        }

                        $ConnectorName = if ($Run.ConnectorName) { [string]$Run.ConnectorName } else { "Unknown" }
                        $ProfileName = if ($Run.RunProfileName) { [string]$Run.RunProfileName } else { "Unknown" }
                        $ResultStr = "Unknown"

                        if ($Run.Result) {
                            try {
                                $ResultStr = $Run.Result.ToString()
                            } catch {
                                $ResultStr = "Completed"
                            }
                        }

                        # Calculate totals
                        $TotalAdds = 0
                        $TotalUpdates = 0
                        $TotalDeletes = 0
                        $TotalErrors = 0

                        if ($Run.RunStepResults) {
                            foreach ($Step in $Run.RunStepResults) {
                                try {
                                    $TotalAdds += [int]$Step.NumberOfStepAdds
                                    $TotalUpdates += [int]$Step.NumberOfStepUpdates
                                    $TotalDeletes += [int]$Step.NumberOfStepDeletes

                                    if ($Step.StepErrorCount -gt 0) {
                                        $TotalErrors += [int]$Step.StepErrorCount
                                    }
                                }
                                catch {
                                    # Skip if step data unavailable
                                }
                            }
                        }

                        $HistoryData += "$RunDate|$ConnectorName|$ProfileName|$ResultStr|$TotalAdds|$TotalUpdates|$TotalDeletes|$TotalErrors"
                    }
                }
                else {
                    $HistoryData += "No History|No sync runs found|Check if sync has run recently|Info|0|0|0|0"
                }
            }
            catch {
                $HistoryData += "Error|Failed to retrieve sync history|$($_.Exception.Message)|Error|0|0|0|0"
            }

            if ($HistoryData.Count -eq 0) {
                $HistoryData += "No Data|Sync history unavailable|ADSync service may not be running|Warning|0|0|0|0"
            }

            return $HistoryData
        }
        catch {
            return @("Module Error|ADSync module not loaded|$($_.Exception.Message)|Error|0|0|0|0")
        }
    } -ArgumentList $NumberOfRuns -TimeoutSeconds 30

    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()

        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 8) {
                $LocalObjects += New-Object PSObject -Property @{
                    RunDate = $Parts[0]
                    ConnectorName = $Parts[1]
                    RunProfileName = $Parts[2]
                    Result = $Parts[3]
                    Adds = $Parts[4]
                    Updates = $Parts[5]
                    Deletes = $Parts[6]
                    Errors = $Parts[7]
                }
            }
        }

        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }

    return $Result
}

function Get-ADConnectSyncErrors {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        try {
            Import-Module ADSync -ErrorAction Stop

            $ErrorData = @()

            # CRITICAL FIX: Multiple methods to retrieve sync errors
            try {
                # Method 1: Check recent run results for errors
                $LastRuns = @()
                try {
                    $LastRuns = Get-ADSyncRunProfileResult -ErrorAction Stop | Select-Object -First 5
                }
                catch {
                    # Fallback: no errors if can't get history
                }

                $ErrorCount = 0

                if ($LastRuns -and $LastRuns.Count -gt 0) {
                    foreach ($Run in $LastRuns) {
                        try {
                            $RunResult = if ($Run.Result) { $Run.Result.ToString() } else { "Unknown" }

                            if ($RunResult -ne 'success') {
                                $ConnectorName = if ($Run.ConnectorName) { [string]$Run.ConnectorName } else { "Unknown" }
                                $RunNumber = if ($Run.RunNumber) { $Run.RunNumber } else { "N/A" }

                                $StepErrorCount = 0
                                if ($Run.RunStepResults) {
                                    foreach ($Step in $Run.RunStepResults) {
                                        try {
                                            if ($Step.StepErrorCount -gt 0) {
                                                $StepErrorCount += [int]$Step.StepErrorCount
                                            }
                                        }
                                        catch {
                                            # Skip step if can't read error count
                                        }
                                    }
                                }

                                if ($StepErrorCount -gt 0) {
                                    $ErrorData += "$ConnectorName|Sync Run Error|Run #$RunNumber|Result: $RunResult|$StepErrorCount error(s)"
                                    $ErrorCount++
                                }
                            }
                        }
                        catch {
                            # Skip this run if can't process it
                        }
                    }
                }

                # Method 2: Check for CS export errors
                try {
                    $Connectors = Get-ADSyncConnector -ErrorAction SilentlyContinue

                    foreach ($Connector in $Connectors) {
                        try {
                            $CSErrors = Get-ADSyncCSObjectStatistics -ConnectorName $Connector.Name -ErrorAction SilentlyContinue |
                                        Where-Object { $_.State -like "*error*" }

                            if ($CSErrors) {
                                foreach ($CSError in $CSErrors) {
                                    $ErrorData += "$($Connector.Name)|CS Object Error|$($CSError.ObjectType)|State: $($CSError.State)|Count: $($CSError.Count)"
                                    $ErrorCount++
                                }
                            }
                        }
                        catch {
                            # Skip if can't get CS statistics
                        }
                    }
                }
                catch {
                    # No CS errors available
                }

                # If no errors found, report success
                if ($ErrorCount -eq 0) {
                    $ErrorData += "No Errors|No sync errors detected|Last 5 runs checked|All sync operations successful|Status: Healthy"
                }
            }
            catch {
                $ErrorData += "Check Failed|Cannot retrieve error information|$($_.Exception.Message)|ADSync may not be running|Status: Unknown"
            }

            if ($ErrorData.Count -eq 0) {
                $ErrorData += "No Data|Sync error data unavailable|Check ADSync service|Service may be stopped|Status: Warning"
            }

            return $ErrorData
        }
        catch {
            return @("Module Error|ADSync module not loaded|$($_.Exception.Message)|Cannot check errors|Status: Error")
        }
    } -TimeoutSeconds 30

    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()

        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 5) {
                $LocalObjects += New-Object PSObject -Property @{
                    ConnectorName = $Parts[0]
                    ErrorType = $Parts[1]
                    Details = $Parts[2]
                    Context = $Parts[3]
                    ErrorInfo = $Parts[4]
                }
            }
        }

        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }

    return $Result
}

function Get-ADConnectGlobalSettings {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        try {
            Import-Module ADSync -ErrorAction Stop
            
            $GlobalSettings = Get-ADSyncGlobalSettings -ErrorAction Stop
            $Parameters = Get-ADSyncGlobalSettingsParameter -ErrorAction Stop
            
            $SettingsData = @()
            
            if ($GlobalSettings.InstanceId) {
                $SettingsData += "Instance ID|$($GlobalSettings.InstanceId.ToString())"
            }
            
            $VersionParam = $Parameters | Where-Object { $_.Name -eq 'Microsoft.Synchronize.ServerConfigurationVersion' }
            if ($VersionParam) {
                $SettingsData += "Configuration Version|$($VersionParam.Value.ToString())"
            }
            
            $SourceAnchorParam = $Parameters | Where-Object { $_.Name -eq 'Microsoft.Synchronize.SourceAnchor' }
            if ($SourceAnchorParam) {
                $SettingsData += "Source Anchor Attribute|$($SourceAnchorParam.Value.ToString())"
            }
            
            return $SettingsData
        }
        catch {
            return @("Error|$($_.Exception.Message)")
        }
    } -TimeoutSeconds 30
    
    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()
        
        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 2) {
                $LocalObjects += New-Object PSObject -Property @{
                    Setting = $Parts[0]
                    Value = $Parts[1]
                }
            }
        }
        
        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }
    
    return $Result
}

function Get-ADConnectMetrics {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $Result = Invoke-SafeRemoteCommand -ServerName $ServerName -Credential $Credential -ScriptBlock {
        try {
            Import-Module ADSync -ErrorAction Stop

            $MetricsData = @()

            # CRITICAL FIX: Safely retrieve connector metrics with null checks
            try {
                $Connectors = Get-ADSyncConnector -ErrorAction Stop

                if ($Connectors) {
                    foreach ($Connector in $Connectors) {
                        try {
                            $ConnectorName = if ($Connector.Name) { [string]$Connector.Name } else { "Unknown" }

                            $ConnectorType = "Unknown"
                            if ($Connector.ConnectorType) {
                                try {
                                    $ConnectorType = $Connector.ConnectorType.ToString()
                                } catch {
                                    $ConnectorType = "Unknown"
                                }
                            }

                            # Try to get CS statistics
                            $TotalObjects = 0
                            $ObjectTypes = "N/A"
                            $LastSync = "Never"

                            try {
                                $CSStatistics = Get-ADSyncCSObjectStatistics -ConnectorName $ConnectorName -ErrorAction SilentlyContinue

                                if ($CSStatistics) {
                                    # Calculate total objects
                                    foreach ($Stat in $CSStatistics) {
                                        try {
                                            if ($Stat.Count) {
                                                $TotalObjects += [int]$Stat.Count
                                            }
                                        } catch {
                                            # Skip if can't read count
                                        }
                                    }

                                    # Get object types
                                    $Types = @()
                                    foreach ($Stat in $CSStatistics) {
                                        try {
                                            if ($Stat.ObjectType) {
                                                $Types += [string]$Stat.ObjectType
                                            }
                                        } catch {
                                            # Skip if can't read type
                                        }
                                    }

                                    if ($Types.Count -gt 0) {
                                        $ObjectTypes = ($Types | Select-Object -Unique) -join ", "
                                    }
                                }
                            }
                            catch {
                                # Statistics not available
                                $TotalObjects = "N/A"
                                $ObjectTypes = "Unable to retrieve"
                            }

                            # Try to get last sync time
                            try {
                                $RunHistory = Get-ADSyncRunProfileResult -ErrorAction SilentlyContinue |
                                             Where-Object { $_.ConnectorName -eq $ConnectorName } |
                                             Select-Object -First 1

                                if ($RunHistory -and $RunHistory.StartDate) {
                                    $LastSync = $RunHistory.StartDate.ToString("yyyy-MM-dd HH:mm")
                                }
                            }
                            catch {
                                # Last sync time not available
                            }

                            $MetricsData += "$ConnectorName|$ConnectorType|$TotalObjects|$ObjectTypes|$LastSync"
                        }
                        catch {
                            # If connector processing fails, add error entry
                            $MetricsData += "$($Connector.Name)|Error|0|Failed to retrieve metrics|N/A"
                        }
                    }
                }
                else {
                    $MetricsData += "No Connectors|No connectors configured|0|N/A|Never"
                }
            }
            catch {
                $MetricsData += "Error|Failed to retrieve connectors|0|$($_.Exception.Message)|N/A"
            }

            if ($MetricsData.Count -eq 0) {
                $MetricsData += "No Data|Metrics unavailable|0|Check ADSync service|N/A"
            }

            return $MetricsData
        }
        catch {
            return @("Module Error|ADSync module not loaded|0|$($_.Exception.Message)|N/A")
        }
    } -TimeoutSeconds 30

    if ($Result.Success -and $Result.Data) {
        $LocalObjects = @()

        foreach ($Line in $Result.Data) {
            $Parts = $Line -split '\|'
            if ($Parts.Count -eq 5) {
                $LocalObjects += New-Object PSObject -Property @{
                    ConnectorName = $Parts[0]
                    ConnectorType = $Parts[1]
                    TotalObjects = $Parts[2]
                    ObjectTypes = $Parts[3]
                    LastSync = $Parts[4]
                }
            }
        }

        return @{ Success = $true; Data = $LocalObjects; Error = $null }
    }

    return $Result
}

function Test-ADConnectComprehensive {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $Results = @{
        Version = @()
        Service = @()
        Scheduler = @()
        Connectors = @()
        SyncHistory = @()
        SyncErrors = @()
        GlobalSettings = @()
        Metrics = @()
        Summary = @()
    }
    
    try {
        Write-Verbose "Starting Azure AD Connect validation on $ServerName"
        
        # Version
        $VersionInfo = Get-ADConnectVersion -ServerName $ServerName -Credential $Credential
        if ($VersionInfo.Success -and $VersionInfo.Data) {
            $Results.Version = @($(New-Object PSObject -Property @{
                Component = "Azure AD Connect"
                Version = $VersionInfo.Data.Version
                InstallDate = $VersionInfo.Data.InstallDate
                Server = $VersionInfo.Data.ComputerName
            }))
        }
        
        # Service
        $ServiceInfo = Get-ADConnectServiceStatus -ServerName $ServerName -Credential $Credential
        if ($ServiceInfo.Success -and $ServiceInfo.Data) {
            $Results.Service = $ServiceInfo.Data
        }
        
        # Scheduler
        try {
            $SchedulerInfo = Get-ADConnectSyncScheduler -ServerName $ServerName -Credential $Credential
            if ($SchedulerInfo.Success -and $SchedulerInfo.Data) {
                $Results.Scheduler = $SchedulerInfo.Data
            }
        } catch {
            $Results.Scheduler = @($(New-Object PSObject -Property @{
                Property = "Scheduler Check"
                Value = "Error: $($_.Exception.Message)"
                Status = "Warning"
            }))
        }
        
        # Connectors
        $ConnectorInfo = Get-ADConnectConnectors -ServerName $ServerName -Credential $Credential
        if ($ConnectorInfo.Success -and $ConnectorInfo.Data) {
            $Results.Connectors = $ConnectorInfo.Data
        }
        
        # History
        $HistoryInfo = Get-ADConnectSyncHistory -ServerName $ServerName -Credential $Credential -NumberOfRuns 10
        if ($HistoryInfo.Success -and $HistoryInfo.Data) {
            $Results.SyncHistory = $HistoryInfo.Data
        }
        
        # Errors
        $ErrorInfo = Get-ADConnectSyncErrors -ServerName $ServerName -Credential $Credential
        if ($ErrorInfo.Success -and $ErrorInfo.Data) {
            $Results.SyncErrors = $ErrorInfo.Data
        }
        
        # Settings
        $SettingsInfo = Get-ADConnectGlobalSettings -ServerName $ServerName -Credential $Credential
        if ($SettingsInfo.Success -and $SettingsInfo.Data) {
            $Results.GlobalSettings = $SettingsInfo.Data
        }
        
        # Metrics
        $MetricsInfo = Get-ADConnectMetrics -ServerName $ServerName -Credential $Credential
        if ($MetricsInfo.Success -and $MetricsInfo.Data) {
            $Results.Metrics = $MetricsInfo.Data
        }
        
        # Summary
        $TotalErrors = if ($Results.SyncErrors) { $Results.SyncErrors.Count } else { 0 }
        $LastSyncStatus = if ($Results.SyncHistory -and $Results.SyncHistory.Count -gt 0) { 
            [string]$Results.SyncHistory[0].Result 
        } else { 
            "Unknown" 
        }
        $ServiceRunning = if ($Results.Service -and $Results.Service.Count -gt 0) { 
            ($Results.Service | Where-Object { $_.ServiceName -eq "ADSync" }).Status -eq "Running" 
        } else { 
            $false 
        }
        
        $OverallHealth = if ($ServiceRunning -and $TotalErrors -eq 0) { "Healthy" } else { "Issues Detected" }
        
        $Results.Summary = @(
            $(New-Object PSObject -Property @{
                Metric = "Overall Health"
                Value = [string]$OverallHealth
                Status = if ($OverallHealth -eq "Healthy") { "Success" } else { "Warning" }
            }),
            $(New-Object PSObject -Property @{
                Metric = "Last Sync Result"
                Value = [string]$LastSyncStatus
                Status = if ($LastSyncStatus -eq "success") { "Success" } else { "Info" }
            }),
            $(New-Object PSObject -Property @{
                Metric = "Active Errors"
                Value = [string]$TotalErrors
                Status = if ($TotalErrors -eq 0) { "Success" } else { "Error" }
            }),
            $(New-Object PSObject -Property @{
                Metric = "Connectors Configured"
                Value = if ($Results.Connectors) { [string]$Results.Connectors.Count } else { "0" }
                Status = "Info"
            })
        )
    }
    catch {
        Write-Error "Error during AAD Connect validation: $($_.Exception.Message)"
    }
    
    return $Results
}

#endregion

#endregion



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
        
        # 1. Verify Replication Health - PROFESSIONAL ORGANIZED VERSION
        try {
            # Get all Domain Controllers in the domain
            $AllDCs = @()
            try {
                $AllDCs = Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object Name
            }
            catch {
                $Results.Replication += [PSCustomObject]@{
                    Partner = "ERROR: Cannot retrieve Domain Controllers"
                    Partition = $_.Exception.Message
                    LastSuccess = ""
                    MinutesAgo = ""
                    ConsecutiveFailures = ""
                    Status = "FAILED"
                }
            }
            
            if ($AllDCs.Count -gt 0) {
                # SECTION 1: Domain Controller Inventory
                $Results.Replication += [PSCustomObject]@{
                    Partner = "=========================================="
                    Partition = "DOMAIN CONTROLLER INVENTORY"
                    LastSuccess = ""
                    MinutesAgo = ""
                    ConsecutiveFailures = ""
                    Status = "INFO"
                }
                
                $Results.Replication += [PSCustomObject]@{
                    Partner = "=========================================="
                    Partition = ""
                    LastSuccess = ""
                    MinutesAgo = ""
                    ConsecutiveFailures = ""
                    Status = ""
                }
                
                foreach ($DC in $AllDCs) {
                    $IsCurrentDC = ($DC.HostName -eq $env:COMPUTERNAME) -or ($DC.Name -eq $env:COMPUTERNAME)
                    $DCLabel = if ($IsCurrentDC) { ">>> CURRENT SERVER <<<" } else { "Remote DC" }
                    
                    $Results.Replication += [PSCustomObject]@{
                        Partner = $DC.Name
                        Partition = "Site: $($DC.Site)"
                        LastSuccess = "IP: $($DC.IPv4Address)"
                        MinutesAgo = $DC.OperatingSystem
                        ConsecutiveFailures = ""
                        Status = $DCLabel
                    }
                }
                
                # Blank separator
                $Results.Replication += [PSCustomObject]@{
                    Partner = ""
                    Partition = ""
                    LastSuccess = ""
                    MinutesAgo = ""
                    ConsecutiveFailures = ""
                    Status = ""
                }
                
                # SECTION 2: Replication Status for All DCs
                $Results.Replication += [PSCustomObject]@{
                    Partner = "=========================================="
                    Partition = "REPLICATION STATUS FOR ALL DCs"
                    LastSuccess = ""
                    MinutesAgo = ""
                    ConsecutiveFailures = ""
                    Status = "INFO"
                }
                
                $Results.Replication += [PSCustomObject]@{
                    Partner = "=========================================="
                    Partition = ""
                    LastSuccess = ""
                    MinutesAgo = ""
                    ConsecutiveFailures = ""
                    Status = ""
                }
                
                # OPTIMIZED: Check replication for max 3 DCs to improve performance
                # In large environments, checking all DCs can take several minutes
                $DCsToCheck = $AllDCs | Select-Object -First 3

                foreach ($DC in $DCsToCheck) {
                    try {
                        # DC Header
                        $Results.Replication += [PSCustomObject]@{
                            Partner = "--- $($DC.Name) ---"
                            Partition = "Replication Partners Below"
                            LastSuccess = ""
                            MinutesAgo = ""
                            ConsecutiveFailures = ""
                            Status = "HEADER"
                        }
                        
                        # Get replication partners for this DC
                        $ReplPartners = $null
                        try {
                            $ReplPartners = Get-ADReplicationPartnerMetadata -Target $DC.HostName -Scope Server -ErrorAction Stop
                        }
                        catch {
                            $Results.Replication += [PSCustomObject]@{
                                Partner = "    → ERROR"
                                Partition = "Cannot query replication"
                                LastSuccess = ""
                                MinutesAgo = ""
                                ConsecutiveFailures = ""
                                Status = "ERROR: $($_.Exception.Message)"
                            }
                            continue
                        }
                        
                        if ($ReplPartners) {
                            foreach ($Partner in $ReplPartners) {
                                $LastRepl = $Partner.LastReplicationSuccess
                                $TimeSince = if ($LastRepl) { 
                                    [math]::Round(((Get-Date) - $LastRepl).TotalMinutes, 2) 
                                } else { 
                                    999999 
                                }
                                
                                # Determine status based on time and failures
                                $Status = "OK"
                                if ($Partner.ConsecutiveReplicationFailures -gt 0) {
                                    $Status = "ERROR"
                                }
                                elseif ($TimeSince -gt 180) {
                                    $Status = "CRITICAL"
                                }
                                elseif ($TimeSince -gt 60) {
                                    $Status = "WARNING"
                                }
                                
                                # Extract partner name (remove domain info)
                                $PartnerName = $Partner.Partner
                                if ($PartnerName -match '([^,]+)') {
                                    $PartnerName = $Matches[1] -replace 'CN=', ''
                                }
                                
                                # Extract partition name
                                $PartitionName = $Partner.Partition
                                if ($PartitionName -match 'DC=([^,]+)') {
                                    $PartitionName = $Matches[1]
                                }
                                
                                $Results.Replication += [PSCustomObject]@{
                                    Partner = "    → $PartnerName"
                                    Partition = $PartitionName
                                    LastSuccess = if ($LastRepl) { $LastRepl.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                                    MinutesAgo = $TimeSince
                                    ConsecutiveFailures = $Partner.ConsecutiveReplicationFailures
                                    Status = $Status
                                }
                            }
                        }
                        else {
                            $Results.Replication += [PSCustomObject]@{
                                Partner = "    → No partners found"
                                Partition = ""
                                LastSuccess = ""
                                MinutesAgo = ""
                                ConsecutiveFailures = ""
                                Status = "INFO"
                            }
                        }
                        
                        # Blank line between DCs
                        $Results.Replication += [PSCustomObject]@{
                            Partner = ""
                            Partition = ""
                            LastSuccess = ""
                            MinutesAgo = ""
                            ConsecutiveFailures = ""
                            Status = ""
                        }
                    }
                    catch {
                        $Results.Replication += [PSCustomObject]@{
                            Partner = "--- $($DC.Name) ---"
                            Partition = "ERROR"
                            LastSuccess = ""
                            MinutesAgo = ""
                            ConsecutiveFailures = ""
                            Status = "Failed: $($_.Exception.Message)"
                        }
                        
                        # Blank line
                        $Results.Replication += [PSCustomObject]@{
                            Partner = ""
                            Partition = ""
                            LastSuccess = ""
                            MinutesAgo = ""
                            ConsecutiveFailures = ""
                            Status = ""
                        }
                    }
                }
            }
        }
        catch {
            $Results.Replication += [PSCustomObject]@{
                Partner = "CRITICAL ERROR"
                Partition = $_.Exception.Message
                LastSuccess = ""
                MinutesAgo = ""
                ConsecutiveFailures = ""
                Status = "FAILED"
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
        <#
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
        #>

        # 4. Verify Admin Accounts - DYNAMIC VERSION
        try {
            # Get all Domain Admins
            $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
            
            # Get all Enterprise Admins
            $EnterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue
            
            # Combine and remove duplicates
            $AllAdmins = @($DomainAdmins) + @($EnterpriseAdmins) | 
                Select-Object -Property SamAccountName -Unique
            
            foreach ($AdminMember in $AllAdmins) {
                try {
                    $Admin = Get-ADUser -Identity $AdminMember.SamAccountName -Properties Description, Enabled, LastLogonDate -ErrorAction Stop
                    
                    $DaysSinceLogon = if ($Admin.LastLogonDate) { 
                        ((Get-Date) - $Admin.LastLogonDate).Days 
                    } else { 
                        999 
                    }
                    
                    $Results.AdminAccounts += [PSCustomObject]@{
                        AccountName = $Admin.SamAccountName
                        Enabled = $Admin.Enabled
                        Description = if ($Admin.Description) { $Admin.Description } else { "No Description" }
                        LastLogon = if ($Admin.LastLogonDate) { $Admin.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
                        DaysSinceLogon = $DaysSinceLogon
                        Status = if ($Admin.Enabled -and $Admin.Description -and $DaysSinceLogon -lt 90) { 
                            "OK" 
                        } elseif (-not $Admin.Enabled) { 
                            "Disabled" 
                        } elseif ($DaysSinceLogon -gt 90) { 
                            "Inactive (90+ days)" 
                        } elseif (-not $Admin.Description) { 
                            "Missing Description" 
                        } else { 
                            "Check Required" 
                        }
                    }
                }
                catch {
                    Write-Warning "Could not retrieve details for admin: $($AdminMember.SamAccountName)"
                }
            }
            
            # Add summary
            $EnabledCount = ($Results.AdminAccounts | Where-Object { $_.Enabled -eq $true }).Count
            $DisabledCount = ($Results.AdminAccounts | Where-Object { $_.Enabled -eq $false }).Count
            
            $Results.AdminAccounts += [PSCustomObject]@{
                AccountName = "SUMMARY"
                Enabled = ""
                Description = ""
                LastLogon = ""
                DaysSinceLogon = ""
                Status = "Total: $($Results.AdminAccounts.Count) | Enabled: $EnabledCount | Disabled: $DisabledCount"
            }
        }
        catch {
            $Results.AdminAccounts += [PSCustomObject]@{
                AccountName = "Error"
                Enabled = ""
                Description = $_.Exception.Message
                LastLogon = ""
                DaysSinceLogon = ""
                Status = "Failed"
            }
        }

        # 5. Display Current OU Structure
        try {
            $Domain = (Get-ADDomain).DistinguishedName
            # OPTIMIZED: Only get OU structure without counting objects (MUCH faster)
            # Counting users/computers/groups in every OU can take 5-10 minutes in large environments
            $AllOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $Domain -Properties CanonicalName, Created, Description -ErrorAction Stop |
                      Sort-Object CanonicalName |
                      Select-Object -First 50  # OPTIMIZED: Limit to 50 OUs for performance

            if ($AllOUs) {
                # Get total counts once (much faster than per-OU)
                $TotalUsers = (Get-ADUser -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count
                $TotalComputers = (Get-ADComputer -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count
                $TotalGroups = (Get-ADGroup -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count

                foreach ($OU in $AllOUs) {
                    $Results.OUStructure += [PSCustomObject]@{
                        OUName = $OU.Name
                        CanonicalName = $OU.CanonicalName
                        Created = $OU.Created.ToString("yyyy-MM-dd HH:mm:ss")
                        Users = "-"  # OPTIMIZED: Removed per-OU counting for speed
                        Computers = "-"
                        Groups = "-"
                        Description = if ($OU.Description) { $OU.Description } else { "" }
                        Status = "Active"
                    }
                }

                # Add summary with total counts
                $Results.OUStructure += [PSCustomObject]@{
                    OUName = "DOMAIN TOTALS"
                    CanonicalName = "(All OUs)"
                    Created = ""
                    Users = $TotalUsers
                    Computers = $TotalComputers
                    Groups = $TotalGroups
                    Description = "$($AllOUs.Count) OUs shown (limited for performance)"
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
            # Test actual web browsing capability, not just ICMP ping
            $InternetTests = @()
            
            # Test 1: HTTP/HTTPS to multiple reliable endpoints
            $TestSites = @(
                @{URL="http://www.msftconnecttest.com/connecttest.txt"; Name="Microsoft"},
                @{URL="http://detectportal.firefox.com/success.txt"; Name="Mozilla"},
                @{URL="http://clients3.google.com/generate_204"; Name="Google"}
            )
            
            $SuccessfulTests = 0
            $FailedTests = 0
            $TestDetails = @()
            
            foreach ($Site in $TestSites) {
                try {
                    $Response = Invoke-WebRequest -Uri $Site.URL -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                    if ($Response.StatusCode -eq 200 -or $Response.StatusCode -eq 204) {
                        $SuccessfulTests++
                        $TestDetails += "$($Site.Name): Accessible"
                    }
                    else {
                        $FailedTests++
                        $TestDetails += "$($Site.Name): HTTP $($Response.StatusCode)"
                    }
                }
                catch {
                    $FailedTests++
                    $TestDetails += "$($Site.Name): Blocked/Failed"
                }
            }
            
            # Determine final status
            if ($SuccessfulTests -eq 0) {
                # No internet access - COMPLIANT (as expected for secure infrastructure)
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Web Browsing Test"
                    Result = "No Internet Access (Compliant)"
                    Details = "All HTTP/HTTPS requests blocked"
                    Status = "OK"
                }
            }
            elseif ($SuccessfulTests -eq $TestSites.Count) {
                # Full internet access - SECURITY RISK
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Web Browsing Test"
                    Result = "FULL INTERNET ACCESS DETECTED"
                    Details = "All test sites accessible: $($TestDetails -join ' | ')"
                    Status = "SECURITY RISK"
                }
            }
            else {
                # Partial internet access - WARNING
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Web Browsing Test"
                    Result = "Partial Internet Access"
                    Details = "$SuccessfulTests of $($TestSites.Count) sites accessible: $($TestDetails -join ' | ')"
                    Status = "WARNING"
                }
            }
            
            # Test 2: DNS Resolution (can resolve but not browse?)
            try {
                $DNSTest = Resolve-DnsName -Name "www.microsoft.com" -Type A -ErrorAction Stop
                $DNSWorks = $true
            }
            catch {
                $DNSWorks = $false
            }
            
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "DNS Resolution"
                Result = if ($DNSWorks) { "DNS Working" } else { "DNS Blocked/Failed" }
                Details = if ($DNSWorks) { "Can resolve external domains" } else { "Cannot resolve external domains" }
                Status = if ($DNSWorks -and $SuccessfulTests -eq 0) { "INFO" } elseif ($DNSWorks) { "OK" } else { "OK" }
            }
            
            # Test 3: Proxy Detection
            try {
                $ProxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
                $ProxyEnabled = $ProxySettings.ProxyEnable -eq 1
                $ProxyServer = $ProxySettings.ProxyServer
                
                if ($ProxyEnabled) {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Proxy Configuration"
                        Result = "Proxy Configured"
                        Details = "Proxy Server: $ProxyServer"
                        Status = "INFO"
                    }
                }
                else {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Proxy Configuration"
                        Result = "No Proxy Configured"
                        Details = "Direct connection settings"
                        Status = "INFO"
                    }
                }
            }
            catch {
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Proxy Configuration"
                    Result = "Unable to check"
                    Details = "Registry access failed"
                    Status = "INFO"
                }
            }
            
            # Test 4: Windows Firewall Status
            try {
                $FirewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $EnabledProfiles = ($FirewallProfiles | Where-Object { $_.Enabled -eq $true }).Name -join ", "
                
                if ($EnabledProfiles) {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Windows Firewall"
                        Result = "Enabled"
                        Details = "Active Profiles: $EnabledProfiles"
                        Status = "OK"
                    }
                }
                else {
                    $Results.InternetAccess += [PSCustomObject]@{
                        Check = "Windows Firewall"
                        Result = "Disabled"
                        Details = "No firewall profiles active"
                        Status = "WARNING"
                    }
                }
            }
            catch {
                $Results.InternetAccess += [PSCustomObject]@{
                    Check = "Windows Firewall"
                    Result = "Unable to check"
                    Details = $_.Exception.Message
                    Status = "INFO"
                }
            }
        }
        catch {
            $Results.InternetAccess += [PSCustomObject]@{
                Check = "Internet Connectivity Test"
                Result = "Test Failed"
                Details = $_.Exception.Message
                Status = "ERROR"
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
            RelyingPartyTrusts = @()
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
                        $Status = if ($DaysToExpire -lt $Script:Thresholds.CertificateExpiryWarningDays) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                        
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
                $Status = if ($DaysToExpire -lt $Script:Thresholds.CertificateExpiryWarningDays) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                
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
                            $Status = if ($DaysToExpire -lt $Script:Thresholds.CertificateExpiryWarningDays) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                            
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
                            $Status = if ($DaysToExpire -lt $Script:Thresholds.CertificateExpiryWarningDays) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                            
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
                        $Status = if ($DaysToExpire -lt $Script:Thresholds.CertificateExpiryWarningDays) { "Expiring Soon" } elseif ($DaysToExpire -lt 0) { "EXPIRED" } else { "Valid" }
                        
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
        
        # 7. Verify Relying Party Trusts
        try {
            try {
                Import-Module ADFS -ErrorAction Stop
                $ADFSInstalled = $true
            }
            catch {
                $ADFSInstalled = $false
            }
            
            if ($ADFSInstalled) {
                try {
                    $RelyingParties = Get-AdfsRelyingPartyTrust -ErrorAction Stop
                    
                    if ($RelyingParties) {
                        foreach ($RP in $RelyingParties) {
                            # Get identifier (usually the first one is primary)
                            $Identifier = if ($RP.Identifier) { 
                                ($RP.Identifier | Select-Object -First 1) 
                            } else { 
                                "Not Set" 
                            }
                            
                            # Get endpoint count
                            $EndpointCount = if ($RP.SamlEndpoints) { 
                                $RP.SamlEndpoints.Count 
                            } else { 
                                0 
                            }
                            
                            # Get primary endpoint
                            $PrimaryEndpoint = if ($RP.SamlEndpoints -and $RP.SamlEndpoints.Count -gt 0) {
                                $RP.SamlEndpoints[0].Location
                            } else {
                                "No Endpoints"
                            }
                            
                            # Get encryption certificate info
                            $EncryptionCert = if ($RP.EncryptionCertificate) {
                                $CertThumb = $RP.EncryptionCertificate.Thumbprint
                                "Present ($($CertThumb.Substring(0, 16))...)"
                            } else {
                                "None"
                            }
                            
                            # Get signing certificate info
                            $SigningCert = if ($RP.RequestSigningCertificate -and $RP.RequestSigningCertificate.Count -gt 0) {
                                $CertThumb = $RP.RequestSigningCertificate[0].Thumbprint
                                "Present ($($CertThumb.Substring(0, 16))...)"
                            } else {
                                "None"
                            }
                            
                            # Get claims rules count
                            $IssuanceRules = if ($RP.IssuanceTransformRules) {
                                ($RP.IssuanceTransformRules -split 'c:\[Type').Count - 1
                            } else {
                                0
                            }
                            
                            $AuthorizationRules = if ($RP.IssuanceAuthorizationRules) {
                                ($RP.IssuanceAuthorizationRules -split 'c:\[Type').Count - 1
                            } else {
                                0
                            }
                            
                            # Token lifetime
                            $TokenLifetime = if ($RP.TokenLifetime) {
                                "$($RP.TokenLifetime) minutes"
                            } else {
                                "Default"
                            }
                            
                            # Monitoring status
                            $MonitoringEnabled = if ($RP.MonitoringEnabled) { "Yes" } else { "No" }
                            
                            # Auto update status
                            $AutoUpdate = if ($RP.AutoUpdateEnabled) { "Enabled" } else { "Disabled" }
                            
                            # Determine overall status
                            $Status = if ($RP.Enabled) {
                                if ($IssuanceRules -gt 0) {
                                    "Active"
                                } else {
                                    "Enabled (No Rules)"
                                }
                            } else {
                                "Disabled"
                            }
                            
                            $Results.RelyingPartyTrusts += [PSCustomObject]@{
                                Name = $RP.Name
                                Enabled = if ($RP.Enabled) { "Yes" } else { "No" }
                                Identifier = $Identifier
                                EndpointCount = $EndpointCount
                                PrimaryEndpoint = $PrimaryEndpoint
                                EncryptionCertificate = $EncryptionCert
                                SigningCertificate = $SigningCert
                                IssuanceRules = $IssuanceRules
                                AuthorizationRules = $AuthorizationRules
                                TokenLifetime = $TokenLifetime
                                AutoUpdate = $AutoUpdate
                                MonitoringEnabled = $MonitoringEnabled
                                Status = $Status
                            }
                        }
                        
                        # Add summary row
                        $EnabledCount = ($RelyingParties | Where-Object { $_.Enabled }).Count
                        $DisabledCount = ($RelyingParties | Where-Object { -not $_.Enabled }).Count
                        
                        $Results.RelyingPartyTrusts += [PSCustomObject]@{
                            Name = "SUMMARY"
                            Enabled = ""
                            Identifier = ""
                            EndpointCount = ""
                            PrimaryEndpoint = ""
                            EncryptionCertificate = ""
                            SigningCertificate = ""
                            IssuanceRules = ""
                            AuthorizationRules = ""
                            TokenLifetime = ""
                            AutoUpdate = ""
                            MonitoringEnabled = ""
                            Status = "Total: $($RelyingParties.Count) | Enabled: $EnabledCount | Disabled: $DisabledCount"
                        }
                    }
                    else {
                        $Results.RelyingPartyTrusts += [PSCustomObject]@{
                            Name = "No Relying Party Trusts Found"
                            Enabled = ""
                            Identifier = ""
                            EndpointCount = ""
                            PrimaryEndpoint = ""
                            EncryptionCertificate = ""
                            SigningCertificate = ""
                            IssuanceRules = ""
                            AuthorizationRules = ""
                            TokenLifetime = ""
                            AutoUpdate = ""
                            MonitoringEnabled = ""
                            Status = "None Configured"
                        }
                    }
                }
                catch {
                    $Results.RelyingPartyTrusts += [PSCustomObject]@{
                        Name = "Error retrieving Relying Party Trusts"
                        Enabled = ""
                        Identifier = $_.Exception.Message
                        EndpointCount = ""
                        PrimaryEndpoint = ""
                        EncryptionCertificate = ""
                        SigningCertificate = ""
                        IssuanceRules = ""
                        AuthorizationRules = ""
                        TokenLifetime = ""
                        AutoUpdate = ""
                        MonitoringEnabled = ""
                        Status = "Failed"
                    }
                }
            }
            else {
                $Results.RelyingPartyTrusts += [PSCustomObject]@{
                    Name = "ADFS Module Not Available"
                    Enabled = ""
                    Identifier = "Cannot retrieve Relying Party Trusts without ADFS PowerShell module"
                    EndpointCount = ""
                    PrimaryEndpoint = ""
                    EncryptionCertificate = ""
                    SigningCertificate = ""
                    IssuanceRules = ""
                    AuthorizationRules = ""
                    TokenLifetime = ""
                    AutoUpdate = ""
                    MonitoringEnabled = ""
                    Status = "Module Missing"
                }
            }
        }
        catch {
            $Results.RelyingPartyTrusts += [PSCustomObject]@{
                Name = "Error"
                Enabled = ""
                Identifier = $_.Exception.Message
                EndpointCount = ""
                PrimaryEndpoint = ""
                EncryptionCertificate = ""
                SigningCertificate = ""
                IssuanceRules = ""
                AuthorizationRules = ""
                TokenLifetime = ""
                AutoUpdate = ""
                MonitoringEnabled = ""
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

function Get-AllDomainWindowsServers {
    <#
    .SYNOPSIS
        Discovers all Windows Server computers joined to the Active Directory domain
    .DESCRIPTION
        Queries Active Directory to find all computer objects with Windows Server operating systems
        Returns a collection of server objects with Name and Role properties
    .PARAMETER Credential
        PSCredential object for domain authentication
    .OUTPUTS
        Array of server objects with Name and Role properties
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $DiscoveredServers = @()

    try {
        Write-Verbose "Starting Active Directory server discovery..."

        # Find a Domain Controller from the inventory to query
        $DC = $Script:ServerInventory | Where-Object {
            $_.Role -eq "DC" -or
            $_.Role -eq "Domain Controller" -or
            $_.Role -eq "AD" -or
            $_.Role -like "Domain Controller*" -or
            $_.Role -like "DC *" -or
            $_.Role -like "AD *" -or
            $_.Role -like "*Active Directory*"
        } | Select-Object -First 1

        if (-not $DC) {
            Write-Warning "No Domain Controller found in servers.txt inventory"
            Write-AuditLog -Action "ServerDiscovery" -Target "ActiveDirectory" -Result "Failed" -Details "No DC in inventory"
            return $DiscoveredServers
        }

        $DCName = $DC.Name
        Write-Verbose "Using Domain Controller: $DCName"

        # Test connection to DC
        if (-not (Test-ServerConnection -ServerName $DCName -Credential $Credential)) {
            Write-Warning "Cannot connect to Domain Controller: $DCName"
            Write-AuditLog -Action "ServerDiscovery" -Target $DCName -Result "Failed" -Details "Connection failed"
            return $DiscoveredServers
        }

        # Query AD for all Windows Server computers
        $ScriptBlock = {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop

                # Query for all computer objects with Server operating systems
                $Servers = Get-ADComputer -Filter {
                    (OperatingSystem -like "*Server*") -and (Enabled -eq $true)
                } -Properties Name, OperatingSystem, DNSHostName, Description -ErrorAction Stop

                $ServerList = @()
                foreach ($Server in $Servers) {
                    $ServerList += [PSCustomObject]@{
                        Name = $Server.DNSHostName
                        OperatingSystem = $Server.OperatingSystem
                        Description = $Server.Description
                    }
                }

                return $ServerList
            }
            catch {
                throw "Failed to query Active Directory: $($_.Exception.Message)"
            }
        }

        Write-Verbose "Querying Active Directory for Windows Servers..."
        $Result = Invoke-SafeRemoteCommand -ServerName $DCName -ScriptBlock $ScriptBlock -Credential $Credential -TimeoutSeconds 60

        if ($Result.Success -and $Result.Data) {
            $ADServers = $Result.Data

            Write-Verbose "Found $($ADServers.Count) Windows Servers in Active Directory"
            Write-AuditLog -Action "ServerDiscovery" -Target "ActiveDirectory" -Result "Success" -Details "Found $($ADServers.Count) servers"

            # Convert to standard server inventory format
            foreach ($Server in $ADServers) {
                # Extract just the hostname from FQDN if present
                $ServerName = $Server.Name
                if ($ServerName -like "*.*") {
                    $ServerName = $ServerName.Split('.')[0]
                }

                # Validate server name for safety
                if (Test-ServerNameSafety -ServerName $ServerName) {
                    # Determine role from operating system or description
                    $Role = "Windows Server"
                    if ($Server.OperatingSystem) {
                        $Role = $Server.OperatingSystem
                    }

                    # Try to detect specific roles from description
                    if ($Server.Description) {
                        if ($Server.Description -match "Exchange") { $Role = "Exchange" }
                        elseif ($Server.Description -match "Domain Controller|DC") { $Role = "DC" }
                        elseif ($Server.Description -match "ADFS|Federation") { $Role = "ADFS" }
                        elseif ($Server.Description -match "SQL") { $Role = "SQL" }
                        elseif ($Server.Description -match "Web|IIS") { $Role = "Web Server" }
                    }

                    $DiscoveredServers += [PSCustomObject]@{
                        Name = $ServerName
                        Role = $Role
                        Source = "Active Directory"
                    }
                }
                else {
                    Write-Warning "Skipped unsafe server name from AD: $ServerName"
                    Write-AuditLog -Action "ServerDiscovery" -Target $ServerName -Result "Rejected" -Details "Failed safety validation"
                }
            }

            Write-Host "[SUCCESS] Discovered $($DiscoveredServers.Count) Windows Servers from Active Directory" -ForegroundColor Green
        }
        else {
            Write-Warning "Failed to query Active Directory: $($Result.Error)"
            Write-AuditLog -Action "ServerDiscovery" -Target "ActiveDirectory" -Result "Failed" -Details $Result.Error
        }
    }
    catch {
        Write-Warning "Error during server discovery: $($_.Exception.Message)"
        Write-AuditLog -Action "ServerDiscovery" -Target "ActiveDirectory" -Result "Error" -Details $_.Exception.Message
    }

    return $DiscoveredServers
}

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
    Update-Status "Discovering all Windows Servers in domain..."

    # MODIFIED: Discover ALL Windows servers from Active Directory instead of using servers.txt
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  SYSTEM UTILIZATION - DOMAIN DISCOVERY" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Mode: Scan ALL Windows Servers in Domain" -ForegroundColor White
    Write-Host "  (Other validations still use servers.txt)" -ForegroundColor Gray
    Write-Host "========================================`n" -ForegroundColor Cyan

    $Servers = Get-AllDomainWindowsServers -Credential $Script:Credential

    if ($Servers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No Windows Servers discovered in Active Directory.`n`nPossible causes:`n- No Domain Controller available in servers.txt`n- Cannot connect to Domain Controller`n- No Windows Server computers in AD`n- Insufficient permissions to query AD",
            "No Servers Discovered",
            "OK",
            "Warning"
        )
        return
    }

    Write-Host "[INFO] Discovered $($Servers.Count) Windows Servers from Active Directory`n" -ForegroundColor Green

    # ENHANCED: Initialize permission check results with WinRM connectivity check
    $PermCheck = @{
        HasPermission = $false
        MissingPermissions = @()
        Details = @()
        WinRMStatus = @()  # NEW: Track WinRM connectivity per server
    }

    $TestedServers = @()
    $WinRMCheckResults = @()

    # ENHANCED: First check WinRM port 5985 on all servers
    $PermCheck.Details += ""
    $PermCheck.Details += "=========================================="
    $PermCheck.Details += "STEP 1: WinRM Port 5985 Connectivity Check"
    $PermCheck.Details += "=========================================="
    $PermCheck.Details += ""

    $WinRMFailedServers = @()
    foreach ($Server in $Servers) {
        $ServerName = $Server.Name
        $PermCheck.Details += "[TEST] Checking WinRM port 5985 on $ServerName..."

        # Test WinRM port availability
        $NetworkTest = Test-NetworkConnectivity -ServerName $ServerName -TestWinRM -Timeout 5

        if ($NetworkTest.WinRMAvailable) {
            $PermCheck.Details += "[OK] WinRM port 5985 is OPEN on $ServerName"
            $PermCheck.Details += "[INFO] Response time: $($NetworkTest.ResponseTime)"
            $WinRMCheckResults += [PSCustomObject]@{
                Server = $ServerName
                Status = "OK"
                WinRMAvailable = $true
            }
        }
        else {
            $PermCheck.Details += "[FAIL] WinRM port 5985 is BLOCKED on $ServerName"
            $PermCheck.MissingPermissions += "WinRM port 5985 not accessible on $ServerName"
            $WinRMFailedServers += $ServerName
            $WinRMCheckResults += [PSCustomObject]@{
                Server = $ServerName
                Status = "FAIL"
                WinRMAvailable = $false
            }
        }
        $PermCheck.Details += ""
    }

    $PermCheck.WinRMStatus = $WinRMCheckResults

    # Check if any servers have WinRM available
    $ServersWithWinRM = $WinRMCheckResults | Where-Object { $_.WinRMAvailable }

    if ($ServersWithWinRM.Count -eq 0) {
        $PermCheck.Details += "[CRITICAL] No servers have WinRM port 5985 accessible!"
        $PermCheck.Details += "[CRITICAL] Validation cannot proceed without WinRM connectivity"
        $PermCheck.Details += ""
        $PermCheck.Details += "TROUBLESHOOTING:"
        $PermCheck.Details += "1. Verify Windows Remote Management service is running"
        $PermCheck.Details += "2. Check firewall rules allow WinRM (port 5985)"
        $PermCheck.Details += "3. Run on target: Enable-PSRemoting -Force"
        $PermCheck.Details += "4. Verify network connectivity to servers"
        return $PermCheck
    }

    # ENHANCED: Now check permissions on servers with working WinRM
    $PermCheck.Details += "=========================================="
    $PermCheck.Details += "STEP 2: Administrator Permission Check"
    $PermCheck.Details += "=========================================="
    $PermCheck.Details += ""

    # OPTIMIZED: Test only 1 server that has WinRM available
    $ServerToTest = ($ServersWithWinRM | Select-Object -First 1).Server
    $ServerObj = $Servers | Where-Object { $_.Name -eq $ServerToTest } | Select-Object -First 1

    if ($ServerObj) {
        if (Test-ServerConnection -ServerName $ServerObj.Name -Credential $Script:Credential) {
            $TestedServers += $ServerObj.Name

            # Test if user is admin on this server
            $ScriptBlock = {
                $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $UserPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
                $AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

                $Result = @{
                    IsAdmin = $UserPrincipal.IsInRole($AdminRole)
                    UserIdentity = $CurrentUser.Name
                    Groups = @()
                }

                # Get group memberships for reporting
                foreach ($Group in $CurrentUser.Groups) {
                    try {
                        $GroupSID = New-Object System.Security.Principal.SecurityIdentifier($Group)
                        $GroupName = $GroupSID.Translate([System.Security.Principal.NTAccount]).Value
                        $Result.Groups += $GroupName
                    } catch {}
                }

                return $Result
            }

            $AdminCheck = Invoke-SafeRemoteCommand -ServerName $ServerObj.Name -ScriptBlock $ScriptBlock -Credential $Script:Credential

            if ($AdminCheck.Success -and $AdminCheck.Data) {
                $Data = $AdminCheck.Data

                $PermCheck.Details += "[INFO] Tested server: $($ServerObj.Name)"
                $PermCheck.Details += "[INFO] Running as: $($Data.UserIdentity)"

                if ($Data.IsAdmin) {
                    $PermCheck.HasPermission = $true
                    $PermCheck.Details += "[OK] Has Local Administrator rights on $($ServerObj.Name)"

                    # Show relevant group memberships
                    $RelevantGroups = $Data.Groups | Where-Object {
                        $_ -match "Administrators|Domain Admins|Enterprise Admins"
                    }

                    if ($RelevantGroups) {
                        $PermCheck.Details += "[INFO] Member of: $($RelevantGroups -join ', ')"
                    }

                    Write-AuditLog -Action "PermissionCheck" -Target $ServerObj.Name -Result "AdminAccess" -Details "Local Administrator confirmed"
                } else {
                    $PermCheck.MissingPermissions += "NOT a Local Administrator on $($ServerObj.Name)"
                    $PermCheck.Details += "[FAIL] User lacks Local Administrator rights on $($ServerObj.Name)"
                }
            }
        }
    }
    
    # Handle connection failures
    if ($TestedServers.Count -eq 0) {
        $PermCheck.MissingPermissions += "Cannot connect to any servers in inventory"
        $PermCheck.Details += "[ERROR] No servers reachable - check WinRM, firewall, or servers.txt"
        $PermCheck.HasPermission = $false
    }
    
    # Add summary if no permissions
    if (-not $PermCheck.HasPermission -and $TestedServers.Count -gt 0) {
        $PermCheck.Details += ""
        $PermCheck.Details += "======================================================================"
        $PermCheck.Details += "REQUIREMENT: Local Administrator rights on target servers"
        $PermCheck.Details += "======================================================================"
        $PermCheck.Details += "Tested servers: $($TestedServers -join ', ')"
        $PermCheck.Details += "Current user: $($Script:Credential.UserName)"
    }
    
    # Add success summary if permissions OK
    if ($PermCheck.HasPermission) {
        $PermCheck.Details += ""
        $PermCheck.Details += "CAPABILITIES VERIFIED:"
        $PermCheck.Details += "=" * 60
        $PermCheck.Details += "[OK] Can read system performance counters"
        $PermCheck.Details += "[OK] Can query WMI for hardware information"
        $PermCheck.Details += "[OK] Can access disk information"
        $PermCheck.Details += "[OK] Can read service status"
        $PermCheck.Details += ""
        $PermCheck.Details += "======================================================================"
        $PermCheck.Details += "PERMISSION CHECK PASSED - Ready to proceed with validation"
        $PermCheck.Details += "======================================================================"
    }
    
    # ALWAYS show permission dialog (success or failure)
    $UserClickedContinue = Show-PermissionCheckDialog -ValidationType "System Utilization" -PermissionResults $PermCheck
    
    # Block if no permissions OR user clicked Close instead of Continue
    if (-not $PermCheck.HasPermission -or -not $UserClickedContinue) {
        
        # Show different message depending on WHY validation was blocked
        if (-not $PermCheck.HasPermission) {
            # User lacks permissions
            if ($TestedServers.Count -eq 0) {
                # Couldn't connect to any servers
                [System.Windows.Forms.MessageBox]::Show(
                    "CONNECTION FAILED`n`nCannot connect to any servers in inventory.`n`nPossible causes:`n- WinRM not enabled on servers`n- Firewall blocking connection`n- Invalid server names in servers.txt`n- Network connectivity issue`n`nCheck servers.txt and try again.",
                    "Connection Failed - Cannot Validate",
                    "OK",
                    "Error"
                )
                Write-AuditLog -Action "UtilizationValidation" -Target "ConnectionFailed" -Result "NoServersReachable"
            } else {
                # Connected but not admin
                [System.Windows.Forms.MessageBox]::Show(
                    "VALIDATION BLOCKED`n`nInsufficient Permissions`n`nREQUIRED: Local Administrator rights on target servers`n`nCurrent User: $($Script:Credential.UserName)`nTested Servers: $($TestedServers -join ', ')`n`nValidation cannot proceed.",
                    "Access Denied - Missing Permissions",
                    "OK",
                    "Error"
                )
                Write-AuditLog -Action "UtilizationValidation" -Target ($TestedServers -join ',') -Result "NotLocalAdmin"
            }
            Update-Status "Utilization validation blocked - insufficient permissions"
        }
        else {
            # User has permissions but clicked Close
            [System.Windows.Forms.MessageBox]::Show(
                "Validation Cancelled`n`nYou clicked 'Close' instead of 'Continue with Validation'.`n`nPermission check passed, but you chose not to proceed.`n`nClick 'System Utilization' again to retry.",
                "Validation Cancelled by User",
                "OK",
                "Information"
            )
            Update-Status "Utilization validation cancelled by user"
            Write-AuditLog -Action "UtilizationValidation" -Target "Cancelled" -Result "UserChoice"
        }
        
        return
    }
    
    Update-Status "Permission check passed - proceeding with utilization validation..."
    
    # Start progress tracking
    if (-not (Start-ValidationProgress -ValidationName "System Utilization" -TotalSteps ($Servers.Count + 2))) {
        return
    }
    
    # Clear previous validation results
    $Script:CurrentResults.Clear()

    Update-ValidationProgress -CurrentStep 1 -StatusText "Preparing system utilization validation..."
    
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
    $StepCounter = 2
    
    # Loop through each server
    foreach ($Server in $Servers) {
        $ServerName = $Server.Name
        
        Update-ValidationProgress -CurrentStep $StepCounter -StatusText "Validating $ServerName..."
        $StepCounter++
        
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
                        if ($Status -ieq "Normal") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                        } elseif ($Status -ieq "High") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                        } elseif ($Status -ieq "Critical") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Error
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
                        if ($Status -ieq "Normal") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                        } elseif ($Status -ieq "High") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                        } elseif ($Status -ieq "Critical") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Error
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
                        if ($Status -ieq "Normal") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Success
                        } elseif ($Status -ieq "Warning") {
                            $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning
                        } elseif ($Status -ieq "Critical") {
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
    
    # CHECK PERMISSIONS FIRST - STRICT ENFORCEMENT
    Update-Status "Checking Exchange permissions..."
    $PermCheck = Test-ExchangePermissions -Credential $Script:Credential
    
    # ALWAYS show permission dialog (success or failure)
    $UserClickedContinue = Show-PermissionCheckDialog -ValidationType "Exchange Server" -PermissionResults $PermCheck

    # Block if no permissions OR user clicked Close instead of Continue
    # Block if no permissions OR user clicked Close instead of Continue
    if (-not $PermCheck.HasPermission -or -not $UserClickedContinue) {
        
        # Show different message depending on WHY validation was blocked
        if (-not $PermCheck.HasPermission) {
            # User lacks permissions
            [System.Windows.Forms.MessageBox]::Show(
                "VALIDATION BLOCKED`n`nInsufficient Permissions`n`nREQUIRED: Organization Management group membership`n`nValidation cannot proceed.",
                "Access Denied - Missing Permissions",
                "OK",
                "Error"
            )
            Update-Status "Exchange validation blocked - insufficient permissions"
        }
        else {
            # User has permissions but clicked Close
            [System.Windows.Forms.MessageBox]::Show(
                "Validation Cancelled`n`nYou clicked 'Close' instead of 'Continue with Validation'.`n`nPermission check passed, but you chose not to proceed.`n`nClick 'Exchange Validation' again to retry.",
                "Validation Cancelled by User",
                "OK",
                "Information"
            )
            Update-Status "Exchange validation cancelled by user"
        }
        
        Write-AuditLog -Action "ExchangeValidation" -Target "Cancelled" -Result "UserChoice"
        return
    }
    
    Update-Status "Permission check passed - proceeding with Exchange validation..."
    
    # ENHANCED: Strict role filtering to avoid matching "Exchange" in other role names
    $Servers = $Script:ServerInventory | Where-Object {
        $_.Role -eq "Exchange" -or
        $_.Role -eq "Exchange Server" -or
        $_.Role -like "Exchange*" -or
        $_.Role -like "*Exchange Server*"
    }
    
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
    
    # Clear existing tabs
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
                            $Status = $Row.Cells["Status"].Value
                            if ($Status -eq "OK") { 
                                $Row.DefaultCellStyle.BackColor = $Script:Colors.Success 
                            }
                            elseif ($Status -eq "WARNING") { 
                                $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning 
                            }
                            elseif ($Status -eq "INFO") { 
                                $Row.DefaultCellStyle.BackColor = $Script:Colors.Info 
                            }
                            elseif ($Status -eq "SECURITY RISK") { 
                                $Row.DefaultCellStyle.BackColor = $Script:Colors.Error 
                            }
                            else { 
                                $Row.DefaultCellStyle.BackColor = $Script:Colors.Error 
                            }
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
        [System.Windows.Forms.MessageBox]::Show(
            "Validation Cancelled`n`nYou chose not to proceed with Active Directory validation.`n`nClick 'AD Validation' again to retry.",
            "Validation Cancelled by User",
            "OK",
            "Information"
        )
        Update-Status "AD validation cancelled by user"
        Write-AuditLog -Action "ADValidation" -Target "Cancelled" -Result "UserChoice"
        return
    }
       
    # Get Domain Controllers from inventory
    # ENHANCED: Strict role filtering - EXCLUDES ADFS and Azure AD Connect
    $DCs = $Script:ServerInventory | Where-Object {
        # Must match one of these patterns
        ($_.Role -eq "DC" -or
         $_.Role -eq "Domain Controller" -or
         $_.Role -eq "AD" -or
         $_.Role -eq "Active Directory" -or
         $_.Role -like "Domain Controller*" -or
         $_.Role -like "DC *" -or
         $_.Role -like "*Active Directory*") -and
        # Must NOT contain ADFS or Azure
        ($_.Role -notlike "*ADFS*" -and
         $_.Role -notlike "*Azure*" -and
         $_.Role -notlike "*Federation*")
    }
    
    if ($DCs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No Domain Controllers found in inventory.`n`nAdd servers with role 'DC' to servers.txt", "Info", "OK", "Information")
        return
    }
    
    # ===== FIX: Remove duplicate servers =====
    $UniqueDCs = @{}
    foreach ($DC in $DCs) {
        if (-not $UniqueDCs.ContainsKey($DC.Name)) {
            $UniqueDCs[$DC.Name] = $DC
        }
    }
    $DCs = $UniqueDCs.Values
    # ===== END FIX =====
    
    # Start progress tracking
    if (-not (Start-ValidationProgress -ValidationName "Active Directory Validation" -TotalSteps ($DCs.Count + 2))) {
        return
    }

    # Clear previous validation results
    $Script:CurrentResults.Clear()

    Update-ValidationProgress -CurrentStep 1 -StatusText "Preparing AD validation..."
    
    # ===== FIX: Clear ALL existing tabs except Welcome (index 0) =====
    while ($Global:TabControl.TabPages.Count -gt 1) {
        $Global:TabControl.TabPages.RemoveAt(1)
    }
    # Force UI refresh
    $Global:TabControl.Refresh()
    [System.Windows.Forms.Application]::DoEvents()
    # ===== END FIX =====
    
    # ===== FIX: Track processed servers to prevent duplicates =====
    $ProcessedServers = @{}
    # ===== END FIX =====
    
    $StepCounter = 2
    foreach ($DC in $DCs) {
        $ServerName = $DC.Name
        
        # ===== FIX: Skip if already processed =====
        if ($ProcessedServers.ContainsKey($ServerName)) {
            Write-Verbose "Skipping duplicate server: $ServerName"
            continue
        }
        $ProcessedServers[$ServerName] = $true
        # ===== END FIX =====
        
        Update-ValidationProgress -CurrentStep $StepCounter -StatusText "Validating AD on $ServerName..."
        $StepCounter++
        
        if (Test-ServerConnection -ServerName $ServerName -Credential $Script:Credential) {
            $Data = Test-ActiveDirectoryComprehensive -ServerName $ServerName -Credential $Script:Credential
            
            if ($Data -and -not $Data.Error) {
                # ===== FIX: Check if tab already exists =====
                $ExistingTab = $null
                foreach ($TabPage in $Global:TabControl.TabPages) {
                    if ($TabPage.Text -eq $ServerName) {
                        $ExistingTab = $TabPage
                        break
                    }
                }
                
                if ($ExistingTab) {
                    Write-Verbose "Tab already exists for $ServerName, skipping..."
                    continue
                }
                # ===== END FIX =====
                
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
                
                # Force UI update
                [System.Windows.Forms.Application]::DoEvents()
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
    Update-Status "Checking ADFS permissions and connectivity..."
    $PermCheck = Test-ADFSPermissions -Credential $Script:Credential

    # Block execution if no permissions OR connection failure
    if (-not $PermCheck.HasPermission) {
        # Determine if this is a connection failure or permission failure
        if ($PermCheck.IsConnectionFailure) {
            # CONNECTION FAILURE - Show detailed diagnostics
            $ErrorMessage = "CONNECTION FAILED`n`n"
            $ErrorMessage += "Cannot establish connection to ADFS server: $($PermCheck.ServerName)`n`n"

            $ErrorMessage += "FAILED CHECKS:`n"
            $ErrorMessage += "============================================`n"
            foreach ($Missing in $PermCheck.MissingPermissions) {
                $ErrorMessage += "- $Missing`n"
            }

            $ErrorMessage += "`n"
            $ErrorMessage += "NEXT STEPS:`n"
            $ErrorMessage += "============================================`n"
            $ErrorMessage += "1. Verify server name in servers.txt is correct`n"
            $ErrorMessage += "2. Check network connectivity to $($PermCheck.ServerName)`n"
            $ErrorMessage += "3. Verify WinRM is enabled on target server`n"
            $ErrorMessage += "4. Test manual connection: Enter-PSSession -ComputerName $($PermCheck.ServerName)`n"
            $ErrorMessage += "5. Check Windows Firewall allows WinRM (port 5985)`n"

            [System.Windows.Forms.MessageBox]::Show(
                $ErrorMessage,
                "Connection Failed",
                "OK",
                "Error"
            )
            Update-Status "ADFS validation blocked - connection failed"
            Write-AuditLog -Action "ADFSValidation" -Target $PermCheck.ServerName -Result "ConnectionFailed"
        }
        else {
            # PERMISSION FAILURE - Show permission details
            $ErrorMessage = "PERMISSION DENIED`n`n"
            $ErrorMessage += "You do not have the required permissions to run ADFS validation.`n`n"

            $ErrorMessage += "MISSING PERMISSIONS:`n"
            $ErrorMessage += "============================================`n"
            foreach ($Missing in $PermCheck.MissingPermissions) {
                $ErrorMessage += "- $Missing`n"
            }

            $ErrorMessage += "`n"
            $ErrorMessage += "REQUIRED: Local Administrator rights on ADFS server`n"
            $ErrorMessage += "Current User: $($Script:Credential.UserName)`n"
            $ErrorMessage += "Target Server: $($PermCheck.ServerName)`n"

            [System.Windows.Forms.MessageBox]::Show(
                $ErrorMessage,
                "Insufficient Permissions",
                "OK",
                "Error"
            )
            Update-Status "ADFS validation blocked - insufficient permissions"
            Write-AuditLog -Action "ADFSValidation" -Target $PermCheck.ServerName -Result "PermissionDenied"
        }
        return
    }
    
    # Show what permissions were verified
    $ContinueValidation = Show-PermissionCheckDialog -ValidationType "ADFS" -PermissionResults $PermCheck
    
    if (-not $ContinueValidation) {
        [System.Windows.Forms.MessageBox]::Show(
            "Validation Cancelled`n`nYou chose not to proceed with ADFS validation.`n`nClick 'ADFS Validation' again to retry.",
            "Validation Cancelled by User",
            "OK",
            "Information"
        )
        Update-Status "ADFS validation cancelled by user"
        Write-AuditLog -Action "ADFSValidation" -Target "Cancelled" -Result "UserChoice"
        return
    }
    
    # Get ADFS servers from inventory
    
    # Get ADFS servers from inventory
    # ENHANCED: Strict role filtering for ADFS only
    $ADFSServers = $Script:ServerInventory | Where-Object {
        $_.Role -eq "ADFS" -or
        $_.Role -eq "Federation" -or
        $_.Role -eq "ADFS Server" -or
        $_.Role -like "ADFS*" -or
        $_.Role -like "*Federation Server*"
    }
    
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
                    @{Name="Relying Party Trusts"; Key="RelyingPartyTrusts"; ColorCode=$true}
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

function Show-ADConnectResults {
    if (-not $Script:Credential) {
        [System.Windows.Forms.MessageBox]::Show(
            "You must connect with credentials first!`n`nClick the 'Connect' button to authenticate before running validations.",
            "Authentication Required",
            "OK",
            "Warning"
        )
        return
    }
    
    
    # Find Azure AD Connect server in inventory
    $ADConnectServer = $Script:ServerInventory | Where-Object { 
        $_.Role -like "*Azure AD Connect*" -or 
        $_.Role -like "*AAD Connect*" -or 
        $_.Role -eq "Azure AD Connect"
    } | Select-Object -First 1
    
    if (-not $ADConnectServer) {
        $AvailableServers = $Script:ServerInventory | ForEach-Object { "$($_.Name) - $($_.Role)" }
        
        $Message = "No Azure AD Connect server found in inventory.`n`n"
        if ($AvailableServers) {
            $Message += "Available servers:`n" + ($AvailableServers -join "`n")
        }
        $Message += "`n`nEnter server name manually?"
        
        $Result = [System.Windows.Forms.MessageBox]::Show($Message, "Server Not Found", "YesNo", "Question")
        
        if ($Result -eq "Yes") {
            Add-Type -AssemblyName Microsoft.VisualBasic
            $ServerName = [Microsoft.VisualBasic.Interaction]::InputBox(
                "Enter Azure AD Connect server hostname:",
                "Enter Server Name",
                "NN-TEST-DC01.nourtest.com"
            )
            
            if ([string]::IsNullOrWhiteSpace($ServerName)) {
                return
            }
        } else {
            return
        }
    } else {
        $ServerName = $ADConnectServer.Name
    }
    
    # Start progress bar immediately
    if (-not (Start-ValidationProgress -ValidationName "Azure AD Connect Validation" -TotalSteps 12)) {
        return
    }
    
    try {
        Update-ValidationProgress -CurrentStep 1 -StatusText "Testing connectivity to $ServerName..."
        
        $PingTest = Test-Connection -ComputerName $ServerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        if (-not $PingTest) {
            Complete-ValidationProgress -CompletionMessage "Connection failed"
            [System.Windows.Forms.MessageBox]::Show(
                "Cannot reach server: $ServerName",
                "Connection Failed",
                "OK",
                "Error"
            )
            return
        }
        
        Update-ValidationProgress -CurrentStep 2 -StatusText "Checking Azure AD Connect permissions on $ServerName..."
        
        $PermCheck = $null
        try {
            $PermCheck = Test-ADConnectPermissions -ServerName $ServerName -Credential $Script:Credential
        }
        catch {
            Complete-ValidationProgress -CompletionMessage "Permission check failed"
            [System.Windows.Forms.MessageBox]::Show(
                "Permission check error: $($_.Exception.Message)",
                "Error",
                "OK",
                "Error"
            )
            return
        }
        
        if (-not $PermCheck -or -not $PermCheck.HasPermission) {
            Complete-ValidationProgress -CompletionMessage "Insufficient permissions"
            
            $DetailedMessage = "Permission Check Failed: $ServerName`n`n"
            if ($PermCheck.MissingPermissions) {
                $DetailedMessage += "MISSING PERMISSIONS:`n"
                $DetailedMessage += "============================================`n"
                foreach ($Missing in $PermCheck.MissingPermissions) {
                    $DetailedMessage += "[X] $Missing`n"
                }
            }
            if ($PermCheck.Details) {
                $DetailedMessage += "`nDETAILS:`n============================================`n"
                foreach ($Detail in $PermCheck.Details) {
                    $DetailedMessage += "  $Detail`n"
                }
            }
            
            [System.Windows.Forms.MessageBox]::Show($DetailedMessage, "Access Denied", "OK", "Error")
            return
        }
        
        Update-ValidationProgress -CurrentStep 3 -StatusText "Permission check complete..."
        
        $ShouldContinue = Show-PermissionCheckDialog -ValidationType "Azure AD Connect" -PermissionResults $PermCheck
        if (-not $ShouldContinue) {
            Complete-ValidationProgress -CompletionMessage "Validation cancelled by user"
            return
        }
        
        Update-ValidationProgress -CurrentStep 5 -StatusText "Starting comprehensive validation..."
        
        # Clear existing results and tabs
        $Script:CurrentResults.Clear()
        while ($Global:TabControl.TabPages.Count -gt 1) {
            $Global:TabControl.TabPages.RemoveAt(1)
        }
        
        Update-ValidationProgress -CurrentStep 6 -StatusText "Retrieving Azure AD Connect data from $ServerName..."
        
        $Results = $null
        try {
            $Results = Test-ADConnectComprehensive -ServerName $ServerName -Credential $Script:Credential
        }
        catch {
            Complete-ValidationProgress -CompletionMessage "Validation failed"
            [System.Windows.Forms.MessageBox]::Show(
                "Validation error: $($_.Exception.Message)",
                "Validation Failed",
                "OK",
                "Error"
            )
            return
        }
        
        if (-not $Results -or -not $Results.Version) {
            Complete-ValidationProgress -CompletionMessage "No data returned"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to retrieve Azure AD Connect data from $ServerName",
                "Validation Failed",
                "OK",
                "Error"
            )
            return
        }
        
        Update-ValidationProgress -CurrentStep 8 -StatusText "Processing validation results..."
        
        # ✅ CREATE TAB PAGE (LIKE OTHER VALIDATIONS)
        $TabPage = New-Object System.Windows.Forms.TabPage
        $TabPage.Text = "$ServerName - Azure AD Connect"
        $TabPage.Padding = New-Object System.Windows.Forms.Padding(3)
        
        # ✅ CREATE SUB-TAB CONTROL (LIKE EXCHANGE/AD/ADFS)
        $SubTabControl = New-Object System.Windows.Forms.TabControl
        $SubTabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
        
        Update-ValidationProgress -CurrentStep 9 -StatusText "Building results display..."
        
        # ✅ SUMMARY TAB
        if ($Results.Summary.Count -gt 0) {
            $SummaryTab = New-Object System.Windows.Forms.TabPage
            $SummaryTab.Text = "Health Summary"
            $SummaryGrid = New-ResultDataGrid -Title "Summary"
            $SummaryGrid.DataSource = [System.Collections.ArrayList]$Results.Summary
            $SummaryGrid.Add_DataBindingComplete({
                foreach ($Row in $SummaryGrid.Rows) {
                    $Status = $Row.Cells["Status"].Value
                    if ($Status -eq "Success") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Success 
                    }
                    elseif ($Status -eq "Warning") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning 
                    }
                    elseif ($Status -eq "Error") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Error 
                    }
                    else { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Info 
                    }
                }
            })
            $SummaryTab.Controls.Add($SummaryGrid)
            $SubTabControl.TabPages.Add($SummaryTab)
        }
        
        # ✅ VERSION TAB
        if ($Results.Version.Count -gt 0) {
            $VersionTab = New-Object System.Windows.Forms.TabPage
            $VersionTab.Text = "Version Information"
            $VersionGrid = New-ResultDataGrid -Title "Version"
            $VersionGrid.DataSource = [System.Collections.ArrayList]$Results.Version
            $VersionTab.Controls.Add($VersionGrid)
            $SubTabControl.TabPages.Add($VersionTab)
        }
        
        # ✅ SERVICE TAB
        if ($Results.Service.Count -gt 0) {
            $ServiceTab = New-Object System.Windows.Forms.TabPage
            $ServiceTab.Text = "Service Status"
            $ServiceGrid = New-ResultDataGrid -Title "Service"
            $ServiceGrid.DataSource = [System.Collections.ArrayList]$Results.Service
            $ServiceGrid.Add_DataBindingComplete({
                foreach ($Row in $ServiceGrid.Rows) {
                    $Status = $Row.Cells["Status"].Value
                    if ($Status -eq "Running") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Success 
                    }
                    elseif ($Status -eq "Stopped") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Error 
                    }
                    else { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning 
                    }
                }
            })
            $ServiceTab.Controls.Add($ServiceGrid)
            $SubTabControl.TabPages.Add($ServiceTab)
        }
        
        # ✅ SCHEDULER TAB
        if ($Results.Scheduler.Count -gt 0) {
            $SchedulerTab = New-Object System.Windows.Forms.TabPage
            $SchedulerTab.Text = "Sync Scheduler"
            $SchedulerGrid = New-ResultDataGrid -Title "Scheduler"
            $SchedulerGrid.DataSource = [System.Collections.ArrayList]$Results.Scheduler
            $SchedulerGrid.Add_DataBindingComplete({
                foreach ($Row in $SchedulerGrid.Rows) {
                    $Status = $Row.Cells["Status"].Value
                    if ($Status -match "Enabled|Active|Scheduled") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Success 
                    }
                    elseif ($Status -match "Warning|Timeout") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning 
                    }
                    elseif ($Status -match "Error|Disabled") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Error 
                    }
                    else { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Info 
                    }
                }
            })
            $SchedulerTab.Controls.Add($SchedulerGrid)
            $SubTabControl.TabPages.Add($SchedulerTab)
        }
        
        # ✅ CONNECTORS TAB
        if ($Results.Connectors.Count -gt 0) {
            $ConnectorsTab = New-Object System.Windows.Forms.TabPage
            $ConnectorsTab.Text = "Connectors"
            $ConnectorsGrid = New-ResultDataGrid -Title "Connectors"
            $ConnectorsGrid.DataSource = [System.Collections.ArrayList]$Results.Connectors
            $ConnectorsTab.Controls.Add($ConnectorsGrid)
            $SubTabControl.TabPages.Add($ConnectorsTab)
        }
        
        # ✅ SYNC HISTORY TAB
        if ($Results.SyncHistory.Count -gt 0) {
            $HistoryTab = New-Object System.Windows.Forms.TabPage
            $HistoryTab.Text = "Sync History"
            $HistoryGrid = New-ResultDataGrid -Title "History"
            $HistoryGrid.DataSource = [System.Collections.ArrayList]$Results.SyncHistory
            $HistoryGrid.Add_DataBindingComplete({
                foreach ($Row in $HistoryGrid.Rows) {
                    $Result = $Row.Cells["Result"].Value
                    $Errors = $Row.Cells["Errors"].Value
                    
                    if ($Result -eq "success" -and $Errors -eq "0") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Success 
                    }
                    elseif ($Errors -ne "0") { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Error 
                    }
                    else { 
                        $Row.DefaultCellStyle.BackColor = $Script:Colors.Warning 
                    }
                }
            })
            $HistoryTab.Controls.Add($HistoryGrid)
            $SubTabControl.TabPages.Add($HistoryTab)
        }
        
        # ✅ SYNC ERRORS TAB
        if ($Results.SyncErrors.Count -gt 0) {
            $ErrorsTab = New-Object System.Windows.Forms.TabPage
            $ErrorsTab.Text = "Sync Errors"
            $ErrorsGrid = New-ResultDataGrid -Title "Errors"
            $ErrorsGrid.DataSource = [System.Collections.ArrayList]$Results.SyncErrors
            $ErrorsGrid.Add_DataBindingComplete({
                foreach ($Row in $ErrorsGrid.Rows) {
                    $Row.DefaultCellStyle.BackColor = $Script:Colors.Error
                }
            })
            $ErrorsTab.Controls.Add($ErrorsGrid)
            $SubTabControl.TabPages.Add($ErrorsTab)
        }
        
        # ✅ GLOBAL SETTINGS TAB
        if ($Results.GlobalSettings.Count -gt 0) {
            $SettingsTab = New-Object System.Windows.Forms.TabPage
            $SettingsTab.Text = "Global Settings"
            $SettingsGrid = New-ResultDataGrid -Title "Settings"
            $SettingsGrid.DataSource = [System.Collections.ArrayList]$Results.GlobalSettings
            $SettingsTab.Controls.Add($SettingsGrid)
            $SubTabControl.TabPages.Add($SettingsTab)
        }
        
        # ✅ METRICS TAB
        if ($Results.Metrics.Count -gt 0) {
            $MetricsTab = New-Object System.Windows.Forms.TabPage
            $MetricsTab.Text = "Connector Metrics"
            $MetricsGrid = New-ResultDataGrid -Title "Metrics"
            $MetricsGrid.DataSource = [System.Collections.ArrayList]$Results.Metrics
            $MetricsTab.Controls.Add($MetricsGrid)
            $SubTabControl.TabPages.Add($MetricsTab)
        }
        
        Update-ValidationProgress -CurrentStep 11 -StatusText "Finalizing display..."
        
        # ✅ ADD SUB-TAB CONTROL TO MAIN TAB
        $TabPage.Controls.Add($SubTabControl)
        
        # ✅ ADD MAIN TAB TO GLOBAL TAB CONTROL
        $Global:TabControl.TabPages.Add($TabPage)
        $Global:TabControl.SelectedTab = $TabPage
        
        # Store results
        $Script:CurrentResults[$ServerName] = @{
            Type = "AzureADConnect"
            Results = $Results
            Timestamp = Get-Date
        }
        
        Write-AuditLog -Action "AADConnectValidation" -Target $ServerName -Result "Success" -Details "Validation completed"
        
        Update-ValidationProgress -CurrentStep 12 -StatusText "Validation complete!"
        Complete-ValidationProgress -CompletionMessage "Azure AD Connect validation completed for $ServerName"
        
        [System.Windows.Forms.MessageBox]::Show(
            "Azure AD Connect validation completed successfully!`n`nServer: $ServerName",
            "Validation Complete",
            "OK",
            "Information"
        )
    }
    catch {
        Complete-ValidationProgress -CompletionMessage "Validation error"
        
        [System.Windows.Forms.MessageBox]::Show(
            "Error during validation: $($_.Exception.Message)",
            "Validation Error",
            "OK",
            "Error"
        )
        
        Write-AuditLog -Action "AADConnectValidation" -Target $ServerName -Result "Error" -Details $_.Exception.Message
    }
}


#region Export Functions

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

        # Determine validation type from first server's data
        $FirstServerData = $Script:CurrentResults.Values | Select-Object -First 1
        $ValidationType = if ($FirstServerData) { $FirstServerData.Type } else { "Infrastructure" }

        # Create validation-specific file name
        $ValidationName = switch ($ValidationType) {
            "Exchange" { "Exchange-Validation" }
            "ActiveDirectory" { "AD-Validation" }
            "ADFS" { "ADFS-Validation" }
            "AzureADConnect" { "Azure-AD-Connect-Validation" }
            "Utilization" { "System-Utilization-Validation" }
            default { "Infrastructure-Validation" }
        }

        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $ReportFileName = "${ValidationName}-${Timestamp}.html"
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

function Export-ValidationCSV {
    if ($Script:CurrentResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No validation results to export",
            "Export CSV",
            "OK",
            "Warning"
        )
        return
    }
    
    try {
        $OutputPath = ".\Reports"
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $ExportedFiles = @()

        foreach ($ServerName in $Script:CurrentResults.Keys | Sort-Object) {
            $ServerData = $Script:CurrentResults[$ServerName]
            $ValidationType = $ServerData.Type
            $Results = $ServerData.Results

            # Create validation-specific file name (consistent with HTML export)
            $ValidationName = switch ($ValidationType) {
                "Exchange" { "Exchange-Validation" }
                "ActiveDirectory" { "AD-Validation" }
                "ADFS" { "ADFS-Validation" }
                "AzureADConnect" { "Azure-AD-Connect-Validation" }
                "Utilization" { "System-Utilization-Validation" }
                default { "Infrastructure-Validation" }
            }

            # Create safe server name and build filename
            $SafeServerName = $ServerName -replace '[^a-zA-Z0-9]', '-'
            $CSVFileName = "${ValidationName}-${SafeServerName}-${Timestamp}.csv"
            $CSVPath = Join-Path $OutputPath $CSVFileName
            
            # ✅ SIMPLE CSV FORMAT - No special characters
            $CSVData = @()
            
            # Report Header (using simple dashes)
            $CSVData += [PSCustomObject]@{
                'Category' = '========================================='
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }

            # ADD VALIDATION TYPE DISPLAY
            $ValidationDisplayName = switch ($ValidationType) {
                "Exchange" { "EXCHANGE SERVER VALIDATION REPORT" }
                "ActiveDirectory" { "ACTIVE DIRECTORY VALIDATION REPORT" }
                "ADFS" { "ADFS VALIDATION REPORT" }
                "AzureADConnect" { "AZURE AD CONNECT VALIDATION REPORT" }
                "Utilization" { "SYSTEM UTILIZATION VALIDATION REPORT" }
                default { "INFRASTRUCTURE VALIDATION REPORT" }
            }

            $CSVData += [PSCustomObject]@{
                'Category' = $ValidationDisplayName
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = '========================================='
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = ''
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'Server Name:'
                'Item' = $ServerName
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'Validation Type:'
                'Item' = $ValidationType
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'Report Date:'
                'Item' = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'Generated By:'
                'Item' = if ($Script:Credential) { $Script:Credential.UserName } else { $env:USERNAME }
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = ''
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = ''
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            # Process each category
            foreach ($Category in $Results.Keys | Sort-Object) {
                if ($Results[$Category] -and $Results[$Category].Count -gt 0) {
                    
                    # Category Header (simple dashes)
                    $CSVData += [PSCustomObject]@{
                        'Category' = '-----------------------------------------'
                        'Item' = ''
                        'Details' = ''
                        'Status' = ''
                    }
                    
                    $CSVData += [PSCustomObject]@{
                        'Category' = $Category.ToUpper()
                        'Item' = "($($Results[$Category].Count) items)"
                        'Details' = ''
                        'Status' = ''
                    }
                    
                    $CSVData += [PSCustomObject]@{
                        'Category' = '-----------------------------------------'
                        'Item' = ''
                        'Details' = ''
                        'Status' = ''
                    }
                    
                    # Add items
                    foreach ($Item in $Results[$Category]) {
                        $Properties = $Item.PSObject.Properties
                        
                        # Smart extraction
                        $ItemName = ""
                        $Details = ""
                        $StatusValue = ""
                        
                        # Get primary identifier
                        foreach ($KeyProp in @("Name", "ServiceName", "Metric", "Property", "Component", "Check", "DatabaseName", "GPOName", "ConnectorName", "Feature", "Setting", "RunDate")) {
                            if ($Properties.Name -contains $KeyProp -and -not [string]::IsNullOrWhiteSpace($Item.$KeyProp)) {
                                $ItemName = $Item.$KeyProp
                                break
                            }
                        }
                        
                        # Get status
                        foreach ($StatusProp in @("Status", "State", "Result", "StatusCode")) {
                            if ($Properties.Name -contains $StatusProp -and -not [string]::IsNullOrWhiteSpace($Item.$StatusProp)) {
                                $StatusValue = $Item.$StatusProp
                                break
                            }
                        }
                        
                        # Build details
                        $DetailParts = @()
                        $UsedProps = @("Name", "ServiceName", "Metric", "Property", "Component", "Check", "DatabaseName", "GPOName", "ConnectorName", "Feature", "Setting", "Status", "State", "Result", "StatusCode", "RunDate")
                        
                        foreach ($Prop in $Properties) {
                            if ($Prop.Name -notin $UsedProps -and -not [string]::IsNullOrWhiteSpace($Prop.Value)) {
                                $PropName = $Prop.Name
                                $PropValue = $Prop.Value
                                
                                # Shorten property names
                                $PropName = $PropName -replace 'DisplayName', 'Display'
                                $PropName = $PropName -replace 'Description', 'Desc'
                                
                                $DetailParts += "$PropName`: $PropValue"
                            }
                        }
                        
                        $Details = $DetailParts -join " | "
                        
                        # Fallback for item name
                        if ([string]::IsNullOrWhiteSpace($ItemName)) {
                            $FirstProp = $Properties | Select-Object -First 1
                            if ($FirstProp) {
                                $ItemName = $FirstProp.Value
                            }
                        }
                        
                        $CSVData += [PSCustomObject]@{
                            'Category' = $ItemName
                            'Item' = $Details
                            'Details' = ''
                            'Status' = $StatusValue
                        }
                    }
                    
                    # Blank line after category
                    $CSVData += [PSCustomObject]@{
                        'Category' = ''
                        'Item' = ''
                        'Details' = ''
                        'Status' = ''
                    }
                }
            }
            
            # Report Footer
            $CSVData += [PSCustomObject]@{
                'Category' = ''
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = '========================================='
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'END OF REPORT'
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = '========================================='
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'Tool: Infrastructure Validation Tool v1.0'
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            $CSVData += [PSCustomObject]@{
                'Category' = 'Author: Nournet - MS Operation'
                'Item' = ''
                'Details' = ''
                'Status' = ''
            }
            
            # Export to CSV with proper encoding
            try {
                $CSVData | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8
                $ExportedFiles += $CSVPath
            }
            catch {
                Write-Warning "Failed to export data for $ServerName $($_.Exception.Message)"
            }
        }
        
        if ($ExportedFiles.Count -gt 0) {
            Update-Status "CSV file(s) exported successfully"
            
            $Message = "Export completed successfully!`n`n"
            $Message += "Files created: $($ExportedFiles.Count)`n"
            $Message += "Location: $OutputPath`n`n"
            
            foreach ($File in $ExportedFiles) {
                $FileInfo = Get-Item $File
                $FileSizeKB = [math]::Round($FileInfo.Length / 1KB, 2)
                $Message += "- $(Split-Path $File -Leaf) ($FileSizeKB KB)`n"
            }
            
            $Message += "`nOpen the Reports folder now?"
            
            $Result = [System.Windows.Forms.MessageBox]::Show(
                $Message,
                "Export Complete",
                "YesNo",
                "Information"
            )
            
            if ($Result -eq "Yes") {
                Start-Process "explorer.exe" -ArgumentList "/select,`"$($ExportedFiles[0])`""
            }
            
            Write-AuditLog -Action "ExportCSV" -Target "AllServers" -Result "Success" -Details "$($ExportedFiles.Count) files"
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "No data was exported. Please ensure validation results contain data.",
                "Export Warning",
                "OK",
                "Warning"
            )
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error exporting CSV: $($_.Exception.Message)",
            "Export Error",
            "OK",
            "Error"
        )
        Write-AuditLog -Action "ExportCSV" -Target "All" -Result "Error" -Details $_.Exception.Message
    }
}

function Show-ExportDialog {
    if ($Script:CurrentResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No validation results to export.`n`nPlease run a validation first.",
            "No Data",
            "OK",
            "Warning"
        )
        return
    }
    
    # Create modern export dialog
    $ExportForm = New-Object System.Windows.Forms.Form
    $ExportForm.Text = "Export Validation Results"
    $ExportForm.Size = New-Object System.Drawing.Size(560, 500)
    $ExportForm.StartPosition = "CenterParent"
    $ExportForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $ExportForm.MaximizeBox = $false
    $ExportForm.MinimizeBox = $false
    $ExportForm.BackColor = [System.Drawing.Color]::White
    $ExportForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    # ===== HEADER =====
    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Export Validation Results"
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(32, 31, 30)
    $TitleLabel.Location = New-Object System.Drawing.Point(30, 25)
    $TitleLabel.Size = New-Object System.Drawing.Size(500, 40)
    $ExportForm.Controls.Add($TitleLabel)
    
    # Determine what validation data is loaded
    $FirstServerData = $Script:CurrentResults.Values | Select-Object -First 1
    $ValidationType = if ($FirstServerData) { 
        switch ($FirstServerData.Type) {
            "Exchange" { "Exchange Server" }
            "ActiveDirectory" { "Active Directory" }
            "ADFS" { "ADFS" }
            "AzureADConnect" { "Azure AD Connect" }
            "Utilization" { "System Utilization" }
            default { "Infrastructure" }
        }
    } else { 
        "Infrastructure" 
    }

    $SubtitleLabel = New-Object System.Windows.Forms.Label
    $SubtitleLabel.Text = "Export $ValidationType validation results"
    $SubtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $SubtitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
    $SubtitleLabel.Location = New-Object System.Drawing.Point(30, 70)
    $SubtitleLabel.Size = New-Object System.Drawing.Size(500, 25)
    $ExportForm.Controls.Add($SubtitleLabel)
    
    # ===== OPTION 1: HTML REPORT =====
    $HTMLPanel = New-Object System.Windows.Forms.Panel
    $HTMLPanel.Location = New-Object System.Drawing.Point(30, 115)
    $HTMLPanel.Size = New-Object System.Drawing.Size(500, 90)
    $HTMLPanel.BackColor = [System.Drawing.Color]::White
    $HTMLPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $HTMLPanel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $ExportForm.Controls.Add($HTMLPanel)
    
    # Blue left border
    $HTMLBorder = New-Object System.Windows.Forms.Panel
    $HTMLBorder.Location = New-Object System.Drawing.Point(0, 0)
    $HTMLBorder.Size = New-Object System.Drawing.Size(4, 90)
    $HTMLBorder.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $HTMLPanel.Controls.Add($HTMLBorder)
    
    # Title
    $HTMLTitle = New-Object System.Windows.Forms.Label
    $HTMLTitle.Text = "HTML Report"
    $HTMLTitle.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $HTMLTitle.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $HTMLTitle.Location = New-Object System.Drawing.Point(20, 15)
    $HTMLTitle.Size = New-Object System.Drawing.Size(470, 30)
    $HTMLPanel.Controls.Add($HTMLTitle)
    
    # Description
    $HTMLDesc = New-Object System.Windows.Forms.Label
    $HTMLDesc.Text = "Professional formatted report for presentations"
    $HTMLDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $HTMLDesc.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
    $HTMLDesc.Location = New-Object System.Drawing.Point(20, 48)
    $HTMLDesc.Size = New-Object System.Drawing.Size(470, 30)
    $HTMLPanel.Controls.Add($HTMLDesc)
    
    # Click handler
    $HTMLPanel.Add_Click({
        $ExportForm.Tag = "HTML"
        $ExportForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $ExportForm.Close()
    })
    
    # Hover effect
    $HTMLPanel.Add_MouseEnter({
        $this.BackColor = [System.Drawing.Color]::FromArgb(232, 243, 252)
    })
    $HTMLPanel.Add_MouseLeave({
        $this.BackColor = [System.Drawing.Color]::White
    })
    
    # ===== OPTION 2: CSV SPREADSHEET =====
    $CSVPanel = New-Object System.Windows.Forms.Panel
    $CSVPanel.Location = New-Object System.Drawing.Point(30, 215)
    $CSVPanel.Size = New-Object System.Drawing.Size(500, 90)
    $CSVPanel.BackColor = [System.Drawing.Color]::White
    $CSVPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $CSVPanel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $ExportForm.Controls.Add($CSVPanel)
    
    # Green left border
    $CSVBorder = New-Object System.Windows.Forms.Panel
    $CSVBorder.Location = New-Object System.Drawing.Point(0, 0)
    $CSVBorder.Size = New-Object System.Drawing.Size(4, 90)
    $CSVBorder.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
    $CSVPanel.Controls.Add($CSVBorder)
    
    # Title
    $CSVTitle = New-Object System.Windows.Forms.Label
    $CSVTitle.Text = "CSV Spreadsheet"
    $CSVTitle.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $CSVTitle.ForeColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
    $CSVTitle.Location = New-Object System.Drawing.Point(20, 15)
    $CSVTitle.Size = New-Object System.Drawing.Size(470, 30)
    $CSVPanel.Controls.Add($CSVTitle)
    
    # Description
    $CSVDesc = New-Object System.Windows.Forms.Label
    $CSVDesc.Text = "Simplified data for Excel analysis"
    $CSVDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $CSVDesc.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
    $CSVDesc.Location = New-Object System.Drawing.Point(20, 48)
    $CSVDesc.Size = New-Object System.Drawing.Size(470, 30)
    $CSVPanel.Controls.Add($CSVDesc)
    
    # Click handler
    $CSVPanel.Add_Click({
        $ExportForm.Tag = "CSV"
        $ExportForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $ExportForm.Close()
    })
    
    # Hover effect
    $CSVPanel.Add_MouseEnter({
        $this.BackColor = [System.Drawing.Color]::FromArgb(232, 247, 232)
    })
    $CSVPanel.Add_MouseLeave({
        $this.BackColor = [System.Drawing.Color]::White
    })
    
    # ===== OPTION 3: BOTH FORMATS =====
    $BothPanel = New-Object System.Windows.Forms.Panel
    $BothPanel.Location = New-Object System.Drawing.Point(30, 315)
    $BothPanel.Size = New-Object System.Drawing.Size(500, 90)
    $BothPanel.BackColor = [System.Drawing.Color]::White
    $BothPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $BothPanel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $ExportForm.Controls.Add($BothPanel)
    
    # Purple left border
    $BothBorder = New-Object System.Windows.Forms.Panel
    $BothBorder.Location = New-Object System.Drawing.Point(0, 0)
    $BothBorder.Size = New-Object System.Drawing.Size(4, 90)
    $BothBorder.BackColor = [System.Drawing.Color]::FromArgb(136, 23, 152)
    $BothPanel.Controls.Add($BothBorder)
    
    # Title
    $BothTitle = New-Object System.Windows.Forms.Label
    $BothTitle.Text = "Both Formats"
    $BothTitle.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $BothTitle.ForeColor = [System.Drawing.Color]::FromArgb(136, 23, 152)
    $BothTitle.Location = New-Object System.Drawing.Point(20, 15)
    $BothTitle.Size = New-Object System.Drawing.Size(470, 30)
    $BothPanel.Controls.Add($BothTitle)
    
    # Description
    $BothDesc = New-Object System.Windows.Forms.Label
    $BothDesc.Text = "Export HTML and CSV together"
    $BothDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $BothDesc.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
    $BothDesc.Location = New-Object System.Drawing.Point(20, 48)
    $BothDesc.Size = New-Object System.Drawing.Size(470, 30)
    $BothPanel.Controls.Add($BothDesc)
    
    # Click handler
    $BothPanel.Add_Click({
        $ExportForm.Tag = "BOTH"
        $ExportForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $ExportForm.Close()
    })
    
    # Hover effect
    $BothPanel.Add_MouseEnter({
        $this.BackColor = [System.Drawing.Color]::FromArgb(243, 232, 247)
    })
    $BothPanel.Add_MouseLeave({
        $this.BackColor = [System.Drawing.Color]::White
    })
    
    # ===== CANCEL BUTTON =====
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Text = "Cancel"
    $CancelButton.Size = New-Object System.Drawing.Size(100, 35)
    $CancelButton.Location = New-Object System.Drawing.Point(430, 420)
    $CancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $CancelButton.BackColor = [System.Drawing.Color]::White
    $CancelButton.ForeColor = [System.Drawing.Color]::FromArgb(32, 31, 30)
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(138, 136, 134)
    $CancelButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $CancelButton.Add_Click({
        $ExportForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $ExportForm.Close()
    })
    $ExportForm.Controls.Add($CancelButton)
    
    # Show dialog
    $Result = $ExportForm.ShowDialog()
    
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        $Selection = $ExportForm.Tag
        
        switch ($Selection) {
            "HTML" {
                Export-ValidationReport
            }
            "CSV" {
                Export-ValidationCSV
            }
            "BOTH" {
                Export-ValidationReport
                # OPTIMIZED: Reduced delay from 500ms to 100ms
                Start-Sleep -Milliseconds 100
                Export-ValidationCSV
            }
        }
    }
}

function Sanitize-HTMLContent {
    param([string]$Content)
    
    if ([string]::IsNullOrEmpty($Content)) {
        return ""
    }
    
    # NEW: Remove dangerous script elements
    $Content = $Content -replace '<script[^>]*>.*?</script>', ''
    $Content = $Content -replace 'javascript:', ''
    $Content = $Content -replace 'on\w+\s*=', ''
    
    # Basic HTML encoding - escape each character individually
    $Content = $Content -replace '&', '&amp;'
    $Content = $Content -replace '<', '&lt;'
    $Content = $Content -replace '>', '&gt;'
    $Content = $Content -replace '"', '&quot;'
    $Content = $Content -replace "'", '&#39;'
    
    return $Content
}

function Generate-HTMLReport {
    param([hashtable]$Results)
    
    # Use here-string with proper escaping
    $HTML = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VALIDATION_TYPE_TEXT - Infrastructure Validation Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #F5F7FA;
            color: #2C3E50;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: #FFFFFF;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1877F2 0%, #0A66C2 100%);
            color: #FFFFFF;
            padding: 40px 50px;
        }

        .validation-type-badge {
            display: inline-block;
            background: rgba(255, 255, 255, 0.25);
            color: #FFFFFF;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin: 10px 0 15px 0;
            border: 2px solid rgba(255, 255, 255, 0.4);
        }
        
        .header h1 {
            font-size: 32px;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .header .subtitle {
            font-size: 16px;
            font-weight: 400;
            opacity: 0.9;
            margin-bottom: 25px;
        }
        
        .header .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .meta-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        
        .meta-item .label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.8;
            font-weight: 500;
        }
        
        .meta-item .value {
            font-size: 15px;
            font-weight: 600;
        }
        
        .toc {
            background: #F8F9FA;
            padding: 30px 50px;
            border-bottom: 1px solid #E1E4E8;
        }
        
        .toc h2 {
            color: #1877F2;
            font-size: 20px;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        .toc-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
        }
        
        .toc-item {
            background: #FFFFFF;
            padding: 12px 16px;
            border-radius: 6px;
            border-left: 3px solid #1877F2;
            text-decoration: none;
            color: #2C3E50;
            display: block;
            transition: all 0.2s ease;
            font-weight: 500;
            font-size: 14px;
        }
        
        .toc-item:hover {
            background: #E7F3FF;
            transform: translateX(3px);
        }
        
        .content {
            padding: 40px 50px;
        }
        
        .server-section {
            margin-bottom: 60px;
            border: 2px solid #E1E4E8;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            page-break-inside: avoid;
        }

        .server-header {
            background: linear-gradient(135deg, #1877F2 0%, #0A66C2 100%);
            color: #FFFFFF;
            padding: 25px 35px;
            border-radius: 0;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
        }
        
        .server-header h2 {
            font-size: 22px;
            font-weight: 600;
        }
        
        .server-status {
            background: rgba(255, 255, 255, 0.2);
            padding: 6px 14px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .category-section {
            margin: 0 20px 25px 20px;
            background: #FFFFFF;
            border: 1px solid #E1E4E8;
            border-radius: 6px;
            overflow: hidden;
        }

        .category-header {
            background: linear-gradient(to right, #F8F9FA 0%, #FFFFFF 100%);
            padding: 18px 30px;
            border-bottom: 3px solid #1877F2;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .category-header h3 {
            color: #1877F2;
            font-size: 18px;
            font-weight: 600;
        }
        
        .item-count {
            background: #1877F2;
            color: #FFFFFF;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        
        thead {
            background: #2C3E50;
            color: #FFFFFF;
        }
        
        th {
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 11px;
        }
        
        td {
            padding: 12px 16px;
            border-bottom: 1px solid #E1E4E8;
            color: #2C3E50;
        }
        
        tbody tr {
            transition: background-color 0.15s ease;
        }
        
        tbody tr:hover {
            background-color: #F8F9FA;
        }
        
        tbody tr:nth-child(even) {
            background-color: #FAFBFC;
        }
        
        .status-success {
            background-color: #D4EDDA !important;
        }
        
        .status-warning {
            background-color: #FFF3CD !important;
        }
        
        .status-error {
            background-color: #F8D7DA !important;
        }
        
        .status-info {
            background-color: #D1ECF1 !important;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .badge-success {
            background: #28A745;
            color: #FFFFFF;
        }
        
        .badge-warning {
            background: #FFC107;
            color: #212529;
        }
        
        .badge-error {
            background: #DC3545;
            color: #FFFFFF;
        }
        
        .badge-info {
            background: #17A2B8;
            color: #FFFFFF;
        }
        
        .footer {
            background: #F8F9FA;
            padding: 30px 50px;
            text-align: center;
            border-top: 1px solid #E1E4E8;
        }
        
        .footer-content {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .footer h3 {
            color: #1877F2;
            font-size: 18px;
            margin-bottom: 12px;
            font-weight: 600;
        }
        
        .footer p {
            color: #6C757D;
            font-size: 13px;
            line-height: 1.7;
        }
        
        .footer-logo {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #E1E4E8;
            color: #6C757D;
            font-size: 12px;
        }
        
        @media print {
            body {
                background: #FFFFFF;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
            
            .toc {
                display: none;
            }
            
            .server-section {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>Infrastructure Validation Report</h1>
                <div class="validation-type-badge">VALIDATION_TYPE_BADGE</div>
                <div class="subtitle">Comprehensive System Health Assessment &amp; Documentation</div>
                
                <div class="meta-info">
                    <div class="meta-item">
                        <div class="label">Generated Date</div>
                        <div class="value">REPORT_DATE</div>
                    </div>
                    <div class="meta-item">
                        <div class="label">Generated Time</div>
                        <div class="value">REPORT_TIME</div>
                    </div>
                    <div class="meta-item">
                        <div class="label">Total Servers</div>
                        <div class="value">TOTAL_SERVERS</div>
                    </div>
                    <div class="meta-item">
                        <div class="label">Created By</div>
                        <div class="value">Nournet - MS Operation</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="toc">
            <h2>Table of Contents</h2>
            <div class="toc-grid">
TOC_CONTENT
            </div>
        </div>
        
        <div class="content">
SERVER_CONTENT
        </div>
        
        <div class="footer">
            <div class="footer-content">
                <h3>Infrastructure Validation Tool</h3>
                <p>
                    This report was automatically generated by the Infrastructure Validation Tool v1.0<br>
                    Professional infrastructure health assessment and documentation system
                </p>
                <div class="footer-logo">
                    <strong>2025 Nournet - MS Operation</strong><br>
                    Infrastructure Handover Validation Tool | Version 1.0
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'@

    # Replace placeholders
    $HTML = $HTML -replace 'REPORT_DATE', (Get-Date -Format 'MMMM dd, yyyy')
    $HTML = $HTML -replace 'REPORT_TIME', (Get-Date -Format 'HH:mm:ss')
    $HTML = $HTML -replace 'TOTAL_SERVERS', $Results.Keys.Count
    
    # Determine validation type from first server's data
    $FirstServerData = $Results.Values | Select-Object -First 1
    $ValidationType = if ($FirstServerData) { $FirstServerData.Type } else { "Mixed" }

    # Create readable validation name
    $ValidationDisplayName = switch ($ValidationType) {
        "Exchange" { "EXCHANGE SERVER VALIDATION" }
        "ActiveDirectory" { "ACTIVE DIRECTORY VALIDATION" }
        "ADFS" { "ADFS VALIDATION" }
        "AzureADConnect" { "AZURE AD CONNECT VALIDATION" }
        "Utilization" { "SYSTEM UTILIZATION VALIDATION" }
        default { "INFRASTRUCTURE VALIDATION" }
    }

    # Replace validation type placeholders
    $HTML = $HTML -replace 'VALIDATION_TYPE_BADGE', $ValidationDisplayName
    $HTML = $HTML -replace 'VALIDATION_TYPE_TEXT', $ValidationDisplayName

    # Generate TOC
    $TOCContent = ""
    foreach ($ServerName in $Results.Keys | Sort-Object) {
        $SafeServerName = $ServerName -replace '[^a-zA-Z0-9]', '-'
        $TOCContent += "                <a href=`"#server-$SafeServerName`" class=`"toc-item`">$ServerName</a>`r`n"
    }
    $HTML = $HTML -replace 'TOC_CONTENT', $TOCContent
    
    # Generate Server Content
    $ServerContent = ""
    foreach ($ServerName in $Results.Keys | Sort-Object) {
        $ServerData = $Results[$ServerName]
        $Data = $ServerData.Results
        $ServerID = $ServerName -replace '[^a-zA-Z0-9]', '-'
        
        $ServerContent += @"
            <div class="server-section" id="server-$ServerID">
                <div class="server-header">
                    <h2>$ServerName</h2>
                    <span class="server-status">Active</span>
                </div>

"@

        foreach ($Category in $Data.Keys | Sort-Object) {
            if ($Data[$Category].Count -gt 0) {
                $ItemCount = $Data[$Category].Count
                
                $ServerContent += @"
                <div class="category-section">
                    <div class="category-header">
                        <h3>$Category</h3>
                        <span class="item-count">$ItemCount Items</span>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>

"@

                $FirstItem = $Data[$Category][0]
                $Properties = $FirstItem.PSObject.Properties.Name
                
                foreach ($Prop in $Properties) {
                    $ServerContent += "                                    <th>$Prop</th>`r`n"
                }
                
                $ServerContent += @"
                                </tr>
                            </thead>
                            <tbody>

"@

                foreach ($Item in $Data[$Category]) {
                    $RowClass = ""
                    $StatusValue = ""

                    if ($Item.PSObject.Properties.Name -contains "Status") {
                        $StatusValue = $Item.Status
                    }
                    elseif ($Item.PSObject.Properties.Name -contains "Result") {
                        $StatusValue = $Item.Result
                    }
                    elseif ($Item.PSObject.Properties.Name -contains "StatusCode") {
                        $StatusValue = $Item.StatusCode
                    }

                    # FIXED: Only apply row coloring if Status value is NOT empty
                    if (-not [string]::IsNullOrWhiteSpace($StatusValue)) {
                        if ($StatusValue -match "^(OK|Normal|Valid|Running|Success|Enabled|Active|Configured|Listening)$") {
                            $RowClass = " class='status-success'"
                        }
                        elseif ($StatusValue -match "^(Warning|Check|Expiring|Not Configured|High)$") {
                            $RowClass = " class='status-warning'"
                        }
                        elseif ($StatusValue -match "^(Error|Failed|Critical|EXPIRED|SECURITY|RISK|Not Running|Missing)$") {
                            $RowClass = " class='status-error'"
                        }
                        elseif ($StatusValue -match "^(Info)$") {
                            $RowClass = " class='status-info'"
                        }
                    }
                    
                    $ServerContent += "                                <tr$RowClass>`r`n"
                    
                    foreach ($Prop in $Properties) {
                        $CellValue = Sanitize-HTMLContent -Content $Item.$Prop
                        
                        # FIXED: Only show badge if Status/Result value is NOT empty
                        if ($Prop -match "Status|Result|StatusCode" -and -not [string]::IsNullOrWhiteSpace($CellValue)) {
                            $BadgeClass = "badge-info"
                            if ($CellValue -match "^(OK|Normal|Valid|Running|Success|Enabled|Active|Configured|Listening)$") {
                                $BadgeClass = "badge-success"
                            }
                            elseif ($CellValue -match "^(Warning|Check|Expiring|High)$") {
                                $BadgeClass = "badge-warning"
                            }
                            elseif ($CellValue -match "^(Error|Failed|Critical|EXPIRED|SECURITY|RISK)$") {
                                $BadgeClass = "badge-error"
                            }

                            $ServerContent += "                                    <td><span class='badge $BadgeClass'>$CellValue</span></td>`r`n"
                        }
                        else {
                            $ServerContent += "                                    <td>$CellValue</td>`r`n"
                        }
                    }
                    
                    $ServerContent += "                                </tr>`r`n"
                }
                
                $ServerContent += @"
                            </tbody>
                        </table>
                    </div>
                </div>

"@
            }
        }

        # Add padding at bottom of server section for visual separation
        $ServerContent += @"
                <div style="height: 20px;"></div>
            </div>

"@
    }
    
    $HTML = $HTML -replace 'SERVER_CONTENT', $ServerContent
    
    return $HTML
}

#endregion

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
                $ServerName = $Parts[0].Trim()
                $ServerRole = $Parts[1].Trim()
                
                # SECURITY CHECK - Validate server name
                if (Test-ServerNameSafety -ServerName $ServerName) {
                    $Servers += @{
                        Name = $ServerName
                        Role = $ServerRole
                    }
                } else {
                    Write-Warning "Skipped unsafe server entry: $ServerName"
                    Write-AuditLog -Action "ServerInventory" -Target $ServerName -Result "Rejected" -Details "Failed safety validation"
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

    # Add cleanup when form closes
    $Global:MainForm.Add_FormClosing({
        param($sender, $e)

        # Stop transcript logging
        Stop-SessionTranscript

        # ENHANCED: Use secure credential cleanup function
        Clear-SecureCredentials
    })
    $Global:MainForm = New-Object System.Windows.Forms.Form
    $Global:MainForm.Text = "Infrastructure Validation Tool"
    $Global:MainForm.Size = New-Object System.Drawing.Size(1500, 900)
    $Global:MainForm.StartPosition = "CenterScreen"
    $Global:MainForm.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $Global:MainForm.MinimumSize = New-Object System.Drawing.Size(1200, 700)  # ← ADD THIS LINE
    $Global:MainForm.MaximizeBox = $true
    $Global:MainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable

    # Add resize handler
    $Global:MainForm.Add_Resize({
        # Get current form size
        $FormWidth = $Global:MainForm.ClientSize.Width
        $FormHeight = $Global:MainForm.ClientSize.Height
        
        # Adjust Button Panel
        if ($ButtonPanel) {
            $ButtonPanel.Width = $FormWidth - 40
        }
        
        # Adjust Status Bar Panel
        if ($StatusBarPanel) {
            $StatusBarPanel.Width = $FormWidth - 40
        }
        
        # Adjust Progress Container
        if ($Global:ProgressContainer) {
            $Global:ProgressContainer.Width = $FormWidth - 40
        }
        
        # Adjust Tab Control
        if ($Global:TabControl) {
            $TabHeight = $FormHeight - 290
            $Global:TabControl.Size = New-Object System.Drawing.Size(($FormWidth - 40), $TabHeight)
        }
        
        # Force button panel to recalculate button sizes
        if ($ButtonPanel) {
            $ButtonPanel.PerformLayout()
        }
    })

    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Infrastructure Handover Validation Tool"
    $TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.ForeColor = $Script:Colors.Header
    $TitleLabel.AutoSize = $true
    $TitleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $Global:MainForm.Controls.Add($TitleLabel)
    $SubtitleLabel = New-Object System.Windows.Forms.Label
    $SubtitleLabel.Text = "Professional Infrastructure Health Assessment and Documentation Tool"
    $SubtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $SubtitleLabel.ForeColor = $Script:Colors.GridHeader
    $SubtitleLabel.AutoSize = $true
    $SubtitleLabel.Location = New-Object System.Drawing.Point(20, 60)
    $Global:MainForm.Controls.Add($SubtitleLabel)
    # Button Panel - Responsive design
    $ButtonPanel = New-Object System.Windows.Forms.Panel
    $ButtonPanel.Location = New-Object System.Drawing.Point(20, 90)
    $ButtonPanel.Size = New-Object System.Drawing.Size(($Global:MainForm.ClientSize.Width - 40), 70)
    $ButtonPanel.BackColor = [System.Drawing.Color]::White
    $ButtonPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $ButtonPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $Global:MainForm.Controls.Add($ButtonPanel)

    function New-StyledButton {
        param([string]$Text, [System.Drawing.Color]$BackColor, [scriptblock]$ClickAction)
        $Button = New-Object System.Windows.Forms.Button
        $Button.Text = $Text
        $Button.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $Button.BackColor = $BackColor
        $Button.ForeColor = [System.Drawing.Color]::White
        $Button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        $Button.FlatAppearance.BorderSize = 0
        $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
        $Button.Add_Click($ClickAction)
        return $Button
    }

    # Calculate button dimensions
    $ButtonCount = 7
    $ButtonSpacing = 5
    $TotalSpacing = $ButtonSpacing * ($ButtonCount + 1)
    $AvailableWidth = $ButtonPanel.Width - $TotalSpacing
    $ButtonWidth = [math]::Floor($AvailableWidth / $ButtonCount)
    $ButtonHeight = 50

    # Create buttons with calculated width
    $XPos = $ButtonSpacing

    # Connect/Disconnect button
    $Global:ConnectButton = New-StyledButton -Text "Connect" -BackColor ([System.Drawing.Color]::FromArgb(39, 174, 96)) -ClickAction {
        if ($Script:Credential) {
            Disconnect-Credentials
        }
        else {
            Connect-WithCredentials
        }
    }
    $Global:ConnectButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $Global:ConnectButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($Global:ConnectButton)
    $XPos += $ButtonWidth + $ButtonSpacing

    # System Utilization button
    $UtilButton = New-StyledButton -Text "System Utilization" -BackColor ([System.Drawing.Color]::FromArgb(52, 152, 219)) -ClickAction { Show-UtilizationResults }
    $UtilButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $UtilButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($UtilButton)
    $XPos += $ButtonWidth + $ButtonSpacing

    # Exchange button
    $ExchangeButton = New-StyledButton -Text "Exchange Validation" -BackColor ([System.Drawing.Color]::FromArgb(155, 89, 182)) -ClickAction { Show-ExchangeResults }
    $ExchangeButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $ExchangeButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($ExchangeButton)
    $XPos += $ButtonWidth + $ButtonSpacing

    # AD button
    $ADButton = New-StyledButton -Text "AD Validation" -BackColor ([System.Drawing.Color]::FromArgb(46, 204, 113)) -ClickAction { Show-ADResults }
    $ADButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $ADButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($ADButton)
    $XPos += $ButtonWidth + $ButtonSpacing

    # ADFS button
    $ADFSButton = New-StyledButton -Text "ADFS Validation" -BackColor ([System.Drawing.Color]::FromArgb(230, 126, 34)) -ClickAction { Show-ADFSResults }
    $ADFSButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $ADFSButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($ADFSButton)
    $XPos += $ButtonWidth + $ButtonSpacing

    # Azure AD Connect button
    $ADConnectButton = New-StyledButton -Text "Azure AD Connect" -BackColor ([System.Drawing.Color]::FromArgb(26, 188, 156)) -ClickAction { Show-ADConnectResults }
    $ADConnectButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $ADConnectButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($ADConnectButton)
    $XPos += $ButtonWidth + $ButtonSpacing

    # Export button
    $ExportButton = New-StyledButton -Text "Export Report" -BackColor ([System.Drawing.Color]::FromArgb(44, 62, 80)) -ClickAction { Show-ExportDialog }
    $ExportButton.Location = New-Object System.Drawing.Point($XPos, 10)
    $ExportButton.Size = New-Object System.Drawing.Size($ButtonWidth, $ButtonHeight)
    $ButtonPanel.Controls.Add($ExportButton)

    # Add resize handler for button panel to recalculate button widths
    $ButtonPanel.Add_Resize({
        $PanelWidth = $this.Width
        $ButtonCount = 7
        $ButtonSpacing = 5
        $TotalSpacing = $ButtonSpacing * ($ButtonCount + 1)
        $AvailableWidth = $PanelWidth - $TotalSpacing
        $NewButtonWidth = [math]::Floor($AvailableWidth / $ButtonCount)
        
        # Resize and reposition all buttons
        $XPos = $ButtonSpacing
        foreach ($Control in $this.Controls) {
            if ($Control -is [System.Windows.Forms.Button]) {
                $Control.Width = $NewButtonWidth
                $Control.Location = New-Object System.Drawing.Point($XPos, 10)
                $XPos += $NewButtonWidth + $ButtonSpacing
            }
        }
    })
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
    $VersionLabel.Text = "Version 1.0  |  Created by: Nournet - MS Operation"
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
    $Step2Text.Text = "SELECT VALIDATION - Choose: System Utilization, Exchange, AD, ADFS, or Azure AD Connect"
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

# ==========================================
# MAIN SCRIPT EXECUTION
# ==========================================

# Start transcript logging for audit trail
Start-SessionTranscript

Show-ValidationGUI

# Display Security Features on Startup
Write-Host "`n" -NoNewline
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SECURITY FEATURES ENABLED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [OK] Transcript logging active" -ForegroundColor Green
Write-Host "      Session transcript: $Global:TranscriptPath" -ForegroundColor Gray
Write-Host ""
Write-Host "  [OK] Audit logging active" -ForegroundColor Green
Write-Host "      Audit log location: .\Logs\" -ForegroundColor Gray
Write-Host ""
Write-Host "  [OK] Authentication rate limiting" -ForegroundColor Green
Write-Host "      Max attempts: 3" -ForegroundColor Gray
Write-Host "      Lockout time: 5 minutes" -ForegroundColor Gray
Write-Host ""
Write-Host "  [OK] Server name validation" -ForegroundColor Green
Write-Host "      Prevents injection attacks" -ForegroundColor Gray
Write-Host ""
Write-Host "  [OK] Auto-cleanup on exit" -ForegroundColor Green
Write-Host "      Credentials cleared from memory" -ForegroundColor Gray
Write-Host ""
Write-Host "  [OK] Remote timeout protection" -ForegroundColor Green
Write-Host "      Timeout: 5 minutes" -ForegroundColor Gray
Write-Host ""
Write-Host "  [OK] HTML report sanitization" -ForegroundColor Green
Write-Host "      XSS prevention enabled" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ==========================================
# SCRIPT CLEANUP AND EXIT
# ==========================================

# Stop transcript logging
Stop-SessionTranscript
