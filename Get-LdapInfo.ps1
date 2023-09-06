<#
.NAME
    Get-LdapInfo


.SYNOPSIS
    Perform LDAP Queries of the current domain. This requires a user account in order to execute the cmdlet.
    Due to the amount of switches I have not provieded examples for each one. The names are pretty self explanatory.


.NOTES
    Author: Rob Osborne
    ALias: tobor
    Contact: rosborne@osbornepro.com


.LINKS
    https://roberthsoborne.com
    https://osbornepro.com
    https://github.com/tobor88
    https://gitlab.com/tobor88
    https://www.powershellgallery.com/profiles/tobor


.SYNTAX
    Get-LdapInfo [-Detailed] [ -DomainAdmins | -DomainControllers | -UAC ] [-LDAPS]


.PARAMETER
    -LDAPS                  [<SwitchParameter>]
        This switch parameter will perform searches using LDAP over SSL

    -Detailed                  [<SwitchParameter>]
        This switch parameter will display all properties of the rerturned objects


    -DomainControllers         [<SwitchParameter>]
         This switch is used to tell the cmdlet to get a list of the Domain's Controllers


    -AllServers                [<SwitchParameter>]
        This switch is used to obtain a list of all servers in the domain environment


    -AllMemberServers                [<SwitchParameter>]
        This switch is used to obtain a list of all member servers in the environment


    -DomainTrusts                [<SwitchParameter>]
        This switch is used to obtain a list of all trusted and federated domains for the domain


    -DomainAdmins              [<SwitchParameter>]
        The switch parameter is used to tell the cmdlet to obtain a list of members of the Domain Admins Group


    -UACTrusted                [<SwitchParameter>]
        This switch parameter is used to tell the cmdlet to get a list of UAC Permissions that can be delegated


    -NotUACTrusted                [<SwitchParameter>]
        This switch parameter is used to tell the cmdlet to get a list of UAC Permissions that can NOT be delegated


    -SPNNamedObjects                [<SwitchParameter>]
        This switch is used to obtain a list of Service Principal Named objects


    -EnabledUsers              [<SwitchParameter>]
        This switch parameter is used to tell the cmdlet to get a list of enabled user accounts in the domain


    -PossibleExecutives                [<SwitchParameter>]
        This switch is used to obtain a list of possible executives for the company


    -LogonScript               [<SwitchParameter>]
         This switch is used to tell the cmdlet to get a list of users who have logon scriprts assigned

    -ListAllOu               [<SwitchParameter>]
        This siwtch is meant to return a list of all OUs in the domain


    -ListComputer               [<SwitchParameter>]
        This switch is meant to return a list of all computers in the domain


    -ListContacts               [<SwitchParameter>]
        This switch is meant to return a list of contacts in the domain


    -ListUsers               [<SwitchParameter>]
        This switch is meant to return a list of all users in the domain


    -ListGroups               [<SwitchParameter>]
        This switch is meant to return a list of all groups in the domain


    -ListContainers      [<SwitchParameter>]
        This switch is used to return a list of all containers in the domain


    -ListDomainObjects     [<SwitchParameter>]
        This switch is used to return a list of all objects in the domain


    -ListBuiltInContainers        [<SwitchParameter>]
        This switch is used to return a list of built in OU containers in the domain


    -ChangePasswordAtNextLogon    [<SwitchParameter>]
        This switch is used to return a list of users who are set to change their password at next logon


    -PasswordNeverExpires       [<SwitchParameter>]
        This switch is used to obtain a list of users who have passwords that never expire


    -NoPasswordRequired        [<SwitchParameter>]
        This switch parameter is used to get a list of users who do not require a password to sign in


    -NoKerberosPreAuthRequired [<SwitchParameter>]
        This switch parameter is used to get a list of users who do not require preauthentication when being authenticated with Kerberos


    -PasswordsThatHaveNotChangedInYears       [<SwitchParameter>]
        This switch is used to obtain a list of user passwords that have not changed in years


.INPUTS
    SwitchParameters


.OUTPUTS

    IsPublic IsSerial Name                                     BaseType
    -------- -------- ----                                     --------
    True     True     Object[]                                 System.Array


.EXAMPLE

    -------------------------- EXAMPLE 1 --------------------------

    C:\PS> Get-LdapInfo -DomainControllers | Select-Object -Property 'Name','ms-Mcs-AdmPwd'

    # This example gets a list of all the Domain Controllers and displays the local admin password. (Requires Administrator Execution to get password attribute )
    If executed as an administrator you will also receive the local admin password under the ms-Mcs-AdmPwd attribute value.

    -------------------------- EXAMPLE 2 --------------------------

    C:\PS> Get-LdapInfo -AllServers

    # This example lists All Servers in the Domain

    -------------------------- EXAMPLE 3 --------------------------

    C:\PS> Get-LdapInfo -AllMemberServers

    # This example lists all Member Servers in the domain

    -------------------------- EXAMPLE 4 --------------------------

    C:\PS> Get-LdapInfo -DomainTrusts

    # This example lists Federated Trust Domains

    -------------------------- EXAMPLE 5 --------------------------

    C:\PS> Get-LdapInfo -DomainAdmins

    This example lists all Domain Admins in the domain

    -------------------------- EXAMPLE 6 --------------------------

    C:\PS> Get-LdapInfo -UACTrusted

    This example lists users who are trusted with UAC

    -------------------------- EXAMPLE 7 --------------------------

    C:\PS> Get-LdapInfo -NotUACTrusted

    This example lists users who are not trusted for UAC

    -------------------------- EXAMPLE 8 --------------------------

    C:\PS> Get-LdapInfo -SPNNamedObjects

    # This example lists SPN users

    -------------------------- EXAMPLE 9 --------------------------

    C:\PS> Get-LdapInfo -EnabledUsers

    # This example lists all Enabled Users

    -------------------------- EXAMPLE 10 --------------------------

    C:\PS> Get-LdapInfo -PossibleExecutives

    # This example finds users with Direct Reports and no manager possibly indicating an executive

    -------------------------- EXAMPLE 11 --------------------------

    C:\PS> Get-LdapInfo -LogonScript

    # This example lists all users who have logon scripts that execute

    -------------------------- EXAMPLE 12 --------------------------

    C:\PS> Get-LdapInfo -ListAllOU

    This example lists all of the Domains OUs in Acitve Directory

    -------------------------- EXAMPLE 13 --------------------------

    C:\PS> Get-LdapInfo -ListComputers

    This example lists all Active Directory Computers

    -------------------------- EXAMPLE 14 --------------------------

    C:\PS> Get-LdapInfo -ListContacts

    This example lists all Active Directory Contacts

    -------------------------- EXAMPLE 15 --------------------------

    C:\PS> Get-LdapInfo -ListGroups

    # This example lists all Active Directory Groups

    -------------------------- EXAMPLE 16 --------------------------

    C:\PS> Get-LdapInfo -ListGroups

    # This example lists all Active Directory Groups

    -------------------------- EXAMPLE 17 --------------------------

    C:\PS> Get-LdapInfo -ListContainers

    # This example lists Active Directory Containers

    -------------------------- EXAMPLE 18 --------------------------

    C:\PS> Get-LdapInfo -ListDomainObjects

    # This example lists Active Directory Domain Objects

    -------------------------- EXAMPLE 19 --------------------------

    C:\PS> Get-LdapInfo -ListBuiltInObjects

    # This example list Builtin In Active Directory Objects

    -------------------------- EXAMPLE 20 --------------------------

    C:\PS> Get-LdapInfo -ListBuiltInContainers

    This example lists Built In Active Directory Containers

    -------------------------- EXAMPLE 21 --------------------------

    C:\PS> Get-LdapInfo -ChangePasswordAtNextLogon

    This example lists users who are set to change their password at next logon.DESCRIPTION
    If a user does not have a "Logon Name" Configured in AD they will be returned with this results as well.

    -------------------------- EXAMPLE 22 --------------------------

    C:\PS> Get-LdapInfo -PasswordNeverExpires

    This example list users who have passwords that never expire

    -------------------------- EXAMPLE 23 --------------------------

    C:\PS> Get-LdapInfo -NoPasswordRequired

    # This example lists users who do not require a password for sign in

    -------------------------- EXAMPLE 24 --------------------------

    C:\PS> Get-LdapInfo -NoKerberosPreAuthRequired

    # This example lists users where Kerberos Pre Authentication is not enabled

    -------------------------- EXAMPLE 25 --------------------------

    C:\PS> Get-LdapInfo -PasswordsThatHaveNotChangedInYears | Where-Object -Property Path -notlike "*OU=Disabled*"

    # This example lists users who have passwords that have not changed in years who are also not in a Disabled group

    -------------------------- EXAMPLE 26 --------------------------

    C:\PS> Get-LdapInfo -DistributionGroups

    # This example lists all the Distribution Groups in Active Directory

    -------------------------- EXAMPLE 27 --------------------------

    C:\PS> Get-LdapInfo -SecurityGroups

    This example lists all the Security Groups in Active Directory

    -------------------------- EXAMPLE 28 --------------------------

    C:\PS> Get-LdapInfo -BuiltInGroups

    This example lists all Built In Groups in Active Directory

    -------------------------- EXAMPLE 29 --------------------------

    C:\PS> Get-LdapInfo -AllGlobalGroups

    This example lists all Global Groups in Active Directory

    -------------------------- EXAMPLE 30 --------------------------

    C:\PS> Get-LdapInfo -DomainLocalGroups

    # This example list Domain Local Groups from Active Directory

    -------------------------- EXAMPLE 31 --------------------------

    C:\PS> Get-LdapInfo -UniversalGroups

    # This example lists the Universal Groups from Active Directory

    -------------------------- EXAMPLE 32 --------------------------

    C:\PS> Get-LdapInfo -GlobalSecurityGroups

    # This example list Global Security Groups from Active Directory

    -------------------------- EXAMPLE 33 --------------------------

    C:\PS> Get-LdapInfo -UniversalSecurityGroups

    # This example lists Universal Security Gruops from Active Directory

    -------------------------- EXAMPLE 34 --------------------------

    C:\PS> Get-LdapInfo -DomainLocalSecurityGroups

    # This example lists Domain Local Security Groups from Active Directory

    -------------------------- EXAMPLE 35 --------------------------

    C:\PS> Get-LdapInfo -GlobalDistributionGroups

    This example lists Global Distribution Groups from Acitve Directory

#>
Function Get-LdapInfo {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False)]
            [switch][bool]$Detailed,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$LDAPS,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainControllers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$AllServers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$AllMemberServers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainTrusts,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainAdmins,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$UACTrusted,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$NotUACTrusted,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$SPNNamedObjects,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$EnabledUsers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$PossibleExecutives,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$LogonScript,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListAllOU,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListComputers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListContacts,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListUsers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListContainers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListDomainObjects,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListBuiltInContainers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ChangePasswordAtNextLogon,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$PasswordNeverExpires,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$NoPasswordRequired,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$NoKerberosPreAuthRequired,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$PasswordsThatHaveNotChangedInYears,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DistributionGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$SecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$BuiltInGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$AllGLobalGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainLocalGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$UniversalGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$GlobalSecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$UniversalSecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainLocalSecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$GlobalDistributionGroups

        ) # End param

    BEGIN
    {

        Write-Verbose "Creating LDAP query..."

            If ($DomainControllers.IsPresent) {$LdapFilter = "(primaryGroupID=516)"}
            ElseIf ($AllServers.IsPresent) {$LdapFilter = '(&(objectCategory=computer)(operatingSystem=*server*))'}
            ElseIf ($AllMemberServers.IsPresent) {$LdapFilter = '(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'}
            ElseIf ($DomainTrusts.IsPresent) {$LdapFilter = '(objectClass=trustedDomain)'}

            ElseIf ($DomainAdmins.IsPresent) {$LdapFilter =  "(&(objectCategory=person)(objectClass=user)((memberOf=CN=Domain Admins,OU=Admin Accounts,DC=usav,DC=org)))"}
            ElseIf ($UACTrusted.IsPresent) {$LdapFilter =  "(userAccountControl:1.2.840.113556.1.4.803:=524288)"}
            ElseIf ($NotUACTrusted.IsPresent) {$LdapFilter = '(userAccountControl:1.2.840.113556.1.4.803:=1048576)'}
            ElseIf ($SPNNamedObjects.IsPresent) {$LdapFilter = '(servicePrincipalName=*)'}
            ElseIf ($EnabledUsers.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'}
            ElseIf ($PossibleExecutives.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(directReports=*)(!(manager=*)))'}
            ElseIf ($LogonScript.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(scriptPath=*))'}

            ElseIf ($ListAllOU.IsPresent) {$LdapFilter = '(objectCategory=organizationalUnit)'}
            ElseIf ($ListComputers.IsPresent) {$LdapFilter = '(objectCategory=computer)'}
            ElseIf ($ListContacts.IsPresent) {$LdapFilter = '(objectClass=contact)'}
            ElseIf ($ListUsers.IsPresent) {$LdapFilter = 'samAccountType=805306368'}
            ElseIf ($ListGroups.IsPresent) {$LdapFilter = '(objectCategory=group)'}
            ElseIf ($ListContainers.IsPresent) {$LdapFilter = '(objectCategory=container)'}
            ElseIf ($ListDomainObjects.IsPresent) {$LdapFilter = '(objectCategory=domain)'}
            ElseIf ($ListBuiltInContainers.IsPresent) {$LdapFilter = '(objectCategory=builtinDomain)'}

            ElseIf ($ChangePasswordAtNextLogon.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))'}
            ElseIf ($PasswordNeverExpires.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user) (userAccountControl:1.2.840.113556.1.4.803:=65536))'}
            ElseIf ($NoPasswordRequired.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user) (userAccountControl:1.2.840.113556.1.4.803:=32))'}
            ElseIf ($NoKerberosPreAuthRequired.IsPresent) {'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'}
            ElseIf ($PasswordsThatHaveNotChangedInYears.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user) (pwdLastSet>=129473172000000000))'}

            ElseIf ($DistributionGroups.IsPresent) {$LdapFilter = '(&(objectCategory=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))'}
            ElseIf ($SecurityGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=2147483648)'}
            ElseIf ($BuiltInGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=1)'}
            ElseIf ($AllGlobalGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=2)'}
            ElseIf ($DomainLocalGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=4)'}
            ElseIf ($UniversalGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=8)'}
            ElseIf ($GlobalSecurityGroups.IsPresent) {$LdapFilter = '(groupType=-2147483646)'}
            ElseIf ($UniversalSecurityGroups.IsPresent) {$LdapFilter = '(groupType=-2147483640)'}
            ElseIf ($DomainLocalSecurityGroups.IsPresent) {$LdapFilter = '(groupType=-2147483644)'}
            ElseIf ($GlobalDistributionGroups.IsPresent) {$LdapFilter = '(groupType=2)'}

            $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry
            $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $ObjDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry

            If ($LDAPS.IsPresent)
            {

                Write-Verbose "[*] LDAP over SSL was specified. Using port 636"
                $SearchString =  "LDAP://" + $PrimaryDC + ":636/"

            }  # End If
            Else
            {

                $SearchString =  "LDAP://" + $PrimaryDC + ":389/"

            }  # End Else
            $PrimaryDC = ($DomainObj.PdcRoleOwner).Name

            $DistinguishedName = "DC=$($DomainObj.Name.Replace('.',',DC='))"
            $SearchString += $DistinguishedName

            $Searcher.SearchRoot = $ObjDomain
            $Searcher.Filter = $LdapFilter
            $Searcher.SearchScope = "Subtree"

        } # End BEGIN

    PROCESS
    {

        $Results = $Searcher.FindAll()

        Write-Verbose "[*] Getting results..."


        If ($Detailed.IsPresent)
        {

            If ($Results.Properties)
            {

                ForEach ($Result in $Results)
                {

                    [array]$ObjProperties = @()

                    ForEach ($Property in $Result.Properties)
                    {

                        $ObjProperties += $Property

                    }  # End ForEach

                    $ObjProperties

                    Write-Host "-----------------------------------------------------------------------`n"

                } # End ForEach

            }  # End If
            Else
            {

                ForEach ($Result in $Results)
                {

                    $Object = $Result.GetDirectoryEntry()
                    $Object

                }  # End ForEach


            }  # End Else

        }  # End If
        Else
        {
            ForEach ($Result in $Results)
            {

                $Object = $Result.GetDirectoryEntry()
                $Object

            }  # End ForEach

        }  # End Else

    } # End PROCESS
    END
    {

        Write-Verbose "[*] LDAP Query complete. "

    } # End END

} # End Get-LdapInfo