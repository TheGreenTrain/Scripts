<#
    Enable-MFA.ps1 - Enables Multi-Factor Authentication on Azure Accounts That Have Gone Through the MFA Setup Process
    Copyright (C) 2021  TheGreenTrain

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

<#
.SYNOPSIS
    Enable MFA on Azure accounts
.DESCRIPTION
    Script enables MFA for Azure accounts.  Will generally check all accounts and enable MFA if StrongAuthenticationMethods have been configured
    but StrongAuthenticationRequirements hasn't been configured for the account.  There are a few exceptions to this:
    $RestrictGroups - Accounts that are members of these groups will have MFA enabled $MFADays days after account creation, even if StrongAuthenticationMethods haven't been configured
                      They will receive an email notification 7 days prior to this.
    $ExcludeGroups - Accounts that are members of these groups are excluded from forced MFA if they are also a member of $RestrictGroups
.EXAMPLE
    PS C:\> .\Enable-MFA.ps1
    There's only one way to run the script.  It's meant to be run from a scheduled task.
.INPUTS
    None.  All script options are defined in "User Defined Variables"
.OUTPUTS
    Sends email notifications to $AdminTo when when MFA is enabled (or when there are errors attempting to enable MFA)
    Sends email notifications to $RestrictGroups members $HeadsUpDays days prior to forcing MFA
.NOTES
    Written and tested with PowerShell 5.1
    IMPORTANT:  Run script manually at least once using the account that will be used to launch the scheduled task, on the server where it will be scheduled, so that credentials can
                be stored.
    Required: MSOnline module:  https://docs.microsoft.com/en-us/powershell/module/msonline/?view=azureadps-1.0
    Required:  Microsoft Secret Management Module (https://github.com/PowerShell/SecretManagement):  Install-Module Microsoft.PowerShell.SecretManagement
    Required:  Microsoft Secret Store Module (https://github.com/powershell/secretstore):  Install-Module Microsoft.PowerShell.SecretStore
    MFA Setup Site:  https://aka.ms/MFASetup
#>


#****************************#
#***User Defined Variables***#
#****************************#

# Mail server to send notifications through
$SMTPServer = "SMTPServer.yourcompany.com"
# Sending address for administrative notifications (users where MFA was enabled or users where we had an issue enabling MFA)
$AdminFrom = "MFA-Admin@yourcompany.com"
# Recipients of administrative notifications
$AdminTo = @("admin1@yourcompany.com","admin2@yourcompany.com")
# Subject of administrative notifications
$AdminSubject = "Office 365 Multi-Factor Authentication (MFA) Update"
# Address end-user MFA notifications come from
$NotificationFrom = "Help Desk <help@yourcompany.com>"
# Subject of MFA heads-up email notification
$NotificationSubject = "Multi-Factor Authentication"
# Body of the MFA heads-up email notification.  Email is sent as HTML so tag it up as you want.  Email will be addressed to recipient at time of sending.
$NotificationBody = "This is a heads-up that Multi-Factor Authentication (MFA) will automatically be enabled for your Office 365 account in a week. When this happens you will be required to register for MFA before you can use your account. "
$NotificationBody += "If you would like to take care of this ahead of time instructions to do so can be found at [https://your-MFA-docs.company.com]<br><br>"
$NotificationBody += "Please reach out to the helpdesk if you have any questions or need assistance with your MFA setup.  Thanks!<br>"
$NotificationBody += "[Sender]"
# How long after creation date before an account in $EnforcedMFAGroups gets MFA enabled, even if the setup hasn't been completed
$MFADays = 30
# Number of days before MFA is enabled for an account in $EnforcedMFAGroups to send a heads-up notification
$HeadsUpDays = 7
# Names of Active Directory Groups where MFA will be enforced after $MFADays
$EnforcedMFAGroups = @("All_Staff","Workstation Admins")
# Names of Active Directory groups where members are excluded from having MFA enabled
$ExcludeGroups = @("Special Snowflakes","MFA Exclusion")


#*****************************************#
#***Don't Make Changed Below This Point***#
#*****************************************#

Function Use-Secret {
    <#
    .SYNOPSIS
        Simplifies use of Secret Management in automated scripts
    .DESCRIPTION
        Function creates a Secret Vault if needed, retrieves stored Secrets and makes them ready for use, and stores new secrets
        Secrets are stored for the current user on the server running this script
    .Parameter VaultType
        Optional [string].  Defaults to SecretStore
        A short name for the Vault Extension where Secrets will be stored.
        Currently only support SecretStore.  Vault name will be "$($ENV:USERNAME)-$VaultType"
    .Parameter SecretName
        Mandatory [string]
        The name of the Secret we will be creating/retrieving
    .Parameter SecretType
        Mandatory [string]
        Valid options are "String", "Credential", or "Object"
        What kind of Secret we're creating/retrieving.
    .Parameter SecretObject
        Optional [object]
        Passed object gets stored as a secret
    .EXAMPLE
        Local SecretStore examples
        $Secret = Use-Secret -SecretName "<name of Secret>" -SecretType "String"
        $Secret = Use-Secret -SecretName "<name of Secret>" -SecretType "Credential"

        Checks SecretStore configuration and updates it for automated scripting purposes
        Checks for existing SecretStore vault with name "$($ENV:USERNAME)-$VaultType" and creates it if necessary
        Gets Secret with name SecretName if it exists.  If not user will be prompted to enter Secret of indicated $SecretType
        Returns Secret.  Strings will be returned in cleartext.

        $Obj = New-Object PSObject @{
            Oauth-Client-ID = "This is an ID"
            Oauth-Client-Secret = "This is a Secret"
        }
        $Secret = Use-Secret -SecretName "<name of Secret>" -SecretType "Object" -SecretObject $Obj
        
        Checks SecretStore configuration and updates it for automated scripting purposes
        Checks for existing SecretStore vault with name "$($ENV:USERNAME)-$VaultType" and creates it if necessary
        Gets Secret with name SecretName if it exists.  If not then passed SecretObject will be saved.
        Returns Secret.

    .OUTPUTS
        Requested Secret.  Strings will be returned in cleartext.
    .NOTES
        Additional VaultTypes are available in PowerShell Gallery (search for SecretManagement).  May update function to support others eventually.
    
        Required modules:
        Microsoft.PowerShell.SecretManagement
        Microsoft.PowerShell.SecretStore
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('SecretStore')]
        [string]
        $VaultType='SecretStore',

        [Parameter(Mandatory)]
        [string]
        $SecretName,
        
        [Parameter(Mandatory)]
        [ValidateSet('String','Credential','Object')]
        [string]
        $SecretType,

        [Parameter()]
        [object]
        $SecretObject
    )

    # Currently only support SecretStore
    Switch($VaultType){
        # Update Secret Store Configuration to remove Password requirement and set Interaction to None
        # Necessary for script automation with stored Secrets
        'SecretStore' {
            $Module = 'Microsoft.PowerShell.SecretStore'
            Write-Host "Checking SecretStore Configuration for settings compatible with automated scripts.  You may be prompted to set a password." -ForegroundColor Red
            Write-Host "If so we will update configuration to remove it" -ForegroundColor Red
            $Config = Get-SecretStoreConfiguration
            If ($Config.Authentication -eq "Password") {
                Write-Host "You will be asked to confirm changing the SecretStore configuration." -ForegroundColor Red
                Write-Host "This allows for using stored credentials in automated scripts." -ForegroundColor Red
                Set-SecretStoreConfiguration -Authentication None -Interaction None -Confirm:$false
            }
        }
    }

    # Check for Secret Vault $VaultName and Register if it doesn't exist
    $VaultName = "$($ENV:USERNAME)-$VaultType"
    Try { Get-SecretVault -Name $VaultName -ErrorAction Stop | Out-Null}
    Catch { Register-SecretVault -Name $VaultName -ModuleName $Module }

    # Try to retrieve Secret $SecretName.  If it doesn't exist create it.
    Try { $Secret = Get-Secret -Name $SecretName -Vault $VaultName -ErrorAction Stop}
    Catch {
        switch ($SecretType) {
            
            "String" { $Secret = Read-Host -Prompt "Enter Secret String to be Stored:" }

            "Credential" { $Secret = Get-Credential -Message "Enter Credentials to be Stored"}
            
            "Object" { 
                If ($Null -eq $SecretObject) { Throw "Objects being stored as Secrets need to be passed when Use-Secret is called" }
                Write-Host "Storing passed object as Secret"
                $Secret = $SecretObject
            }

        }
        Set-Secret -Name $SecretName -Secret $Secret -Vault $VaultName
    }

    # If $Secret is a SecureString convert it to plaintext
    If ($Secret.GetType().Name -eq "SecureString") { $Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)) }
    # If $Secret is an object make sure properties are decrypted
    If ($SecretType -eq "Object") {
        $DecryptSecret = New-Object @{}
        $Encrypted = $False
        ForEach ($Key in $Secret.Keys) {
            If ($Secret.$Key.GetType().Name -eq "SecureString") {
                $Encrypted = $True
                $ThisSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.$Key))
                $DecryptSecret.Add($Key,$ThisSecret)
            }
        }
        If ($Encrypted) { $Secret = $DecryptSecret }
    }

    Return $Secret
}


# Accounts in $EnforcedMFAGroups have MFA enabled if they're older than $OlderThan
$OlderThan = (Get-Date).AddDays(-$MFADays)
# Accounts in $EnforcedMFAGroups receive a heads-up notification if they're within 7 days of having MFA enabled and haven't gone through the setup yet
$NotificationDate = ($OlderThan.AddDays(-$HeadsUpDays)).Date

#Connect to Azure with an account that has enough permissions to manage MFA
Write-Host "Getting credentials to connect to Azure" -ForegroundColor Green
$MSOLCred = Use-Secret -SecretName "MSOL" -SecretType "Credential"
Connect-MsolService -Credential $MSOLCred

# Get all Azure Users
$AzureUsers = Get-MsolUser -All

# Get list of users excluded from MFA
$ExcludeUsers = New-Object System.Collections.Generic.List[string]
ForEach ($Group in $ExcludeGroups){
    $GroupMembers = Get-ADGroupMember -Identity $Group | % {Get-ADUser $_ -Properties UserPrincipalName} | Select-Object UserPrincipalName
    $GroupMembers | % { If (!($ExcludeUsers.Contains($_.UserPrincipalName))) { $ExcludeUsers.Add($_.UserPrincipalName) } }
}

# Get list of users required to have MFA
$EnforcedMFAUsers = New-Object System.Collections.Generic.List[string]
ForEach ($Group in $EnforcedMFAGroups){
    $GroupMembers = Get-ADGroupMember -Identity $Group | % {Get-ADUser $_ -Properties UserPrincipalName} | Select-Object UserPrincipalName
    $GroupMembers | % { If (!($ExcludeUsers.Contains($_.UserPrincipalName)) -and !($EnforcedMFAUsers.Contains($_.UserPrincipalName))) { $EnforcedMFAUsers.Add($_.UserPrincipalName) } }
}

# Create array of users where MFA should be enabled
$ReadyUsers = New-Object System.Collections.Generic.List[object]

# Add users required to have MFA to $ReadyUsers if they've done the MFA setup or their account is older than $OlderThan days
$AzureEnforced = $AzureUsers | ? {$EnforcedMFAUsers.Contains($_.UserPrincipalName)}
$TheseUsers = $AzureEnforced | ? {($_.StrongAuthenticationMethods.count -gt 0 -or $_.WhenCreated -lt $OlderThan) -and $_.StrongAuthenticationRequirements.count -eq 0}
If ($TheseUsers.Count -eq 1) { $ReadyUsers.Add($TheseUsers) }
If ($TheseUsers.Count -gt 1) { $ReadyUsers.AddRange($TheseUsers) }

# Get users required to have MFA
# who currently don't
# and are $HeadsUpDays days away from having it enabled, 
# regardless of whether they've done the setup or not
$NotificationUsers = $AzureEnforced | ? {($_.StrongAuthenticationMethods.count -eq 0 -and $($_.WhenCreated).Date -eq $NotificationDate) }

# Add other Azure users to $ReadyUsers if they've done the MFA setup and they aren't in an Excluded Group
$AzureOther = $AzureUsers | ? { !($EnforcedMFAUsers.Contains($_.UserPrincipalName)) -and !($ExcludeUsers.Contains($_.UserPrincipalName)) }
$TheseUsers = $AzureOther | ? {$_.StrongAuthenticationMethods.count -gt 0 -and $_.StrongAuthenticationRequirements.count -eq 0}
If ($TheseUsers.Count -eq 1) { $ReadyUsers.Add($TheseUsers) }
If ($TheseUsers.Count -gt 1) { $ReadyUsers.AddRange($TheseUsers) }

#Create the StrongAuthenticationRequirement object
$MF= New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$MF.RelyingParty = "*"
$MFA = @($MF)

#Enable MFA on accounts in $ReadyUsers
$EnabledUsers = New-Object System.Collections.Generic.List[string]
$ErrorUsers = New-Object System.Collections.Generic.List[object]
ForEach ($User in $ReadyUsers) { 
    $Error.Clear()
    Set-MsolUser -UserPrincipalName $User.UserPrincipalName -StrongAuthenticationRequirements $MFA 
    If ($Error.Count -gt 0) {
        $ThisError = New-Object PSObject @{
            User = $User.UserPrincipalName
            Error = $Error[0].ToString()
        }
        $ErrorUsers.Add($ThisError)
    }
    Else { $EnabledUsers.Add($User.UserPrincipalName) }
}

#If we've enabled MFA for any accounts and/or seen any errors while attempting to enable MFA, send a notification email
$Body = "<html><body>"
If ($EnabledUsers.Count -gt 0) {
    $Body = "MFA has been enabled for the following users:<br><br>"
    $EnabledUsers | % { $Body += "$($_)<br>" }
    $Body += "<br><br>"
}
If ($ErrorUsers.Count -gt 0) {
    $Body += "Encountered an error when trying to enable MFA for the following users:<br><br>"
    $ErrorUsers | % {
        $Body += "$($_.User)<br>"
        $Body += "$($_.Error)<br><br>"
    }
}

If ($Body -ne "<html><body>") {
    $Body += "</html></body>"
    Send-MailMessage -Body $Body -From $AdminFrom -Subject $AdminSubject -To $AdminTo -SmtpServer $SMTPServer -BodyAsHtml
}

# Send MFA heads-up to $NotificationUsers
If ($NotificationUsers.count -gt 0) {
    ForEach ($User in $NotificationUsers) {
        $NotificationTo = $User.UserPrincipalName
        $Body = "<html><body>"
        $Body += "Hi $($User.FirstName),<br><br>"
        $Body += $NotificationBody
        $Body += "</html></body>"
        Send-MailMessage -Body $Body -From $NotificationFrom -To $NotificationTo -Subject $NotificationSubject -SmtpServer $SMTPServer -BodyAsHtml
    }
}