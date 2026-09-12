# ============================================================
# Fictitious Org Builder for corp.local
# Run this on the Domain Controller in an elevated PowerShell
# ============================================================

Import-Module ActiveDirectory

$domain = "DC=corp,DC=local"
$defaultPassword = ConvertTo-SecureString "Passw0rd123!" -AsPlainText -Force

# --- 1. Create top-level OU and department OUs ---
New-ADOrganizationalUnit -Name "CorpUsers" -Path $domain -ProtectedFromAccidentalDeletion $false

$departments = @("IT", "Finance", "HR", "Sales", "Executives")
foreach ($dept in $departments) {
    New-ADOrganizationalUnit -Name $dept -Path "OU=CorpUsers,$domain" -ProtectedFromAccidentalDeletion $false
}

# --- 2. Create security groups per department ---
foreach ($dept in $departments) {
    New-ADGroup -Name "$dept-Users" -GroupScope Global -GroupCategory Security -Path "OU=$dept,OU=CorpUsers,$domain"
}
# Extra admin group for IT
New-ADGroup -Name "IT-Admins" -GroupScope Global -GroupCategory Security -Path "OU=IT,OU=CorpUsers,$domain"

# --- 3. Define users per department (first, last) ---
$users = @{
    "IT"          = @(("Alex","Nguyen"), ("Priya","Rao"), ("Sam","Okafor"))
    "Finance"     = @(("Maria","Lopez"), ("David","Kim"), ("Linda","Chen"))
    "HR"          = @(("Grace","Adams"), ("Tom","Baker"), ("Ella","Fischer"))
    "Sales"       = @(("Jake","Ryan"), ("Nina","Patel"), ("Omar","Hassan"))
    "Executives"  = @(("William","Carter"), ("Sophia","Turner"), ("Henry","Brooks"))
}

foreach ($dept in $users.Keys) {
    foreach ($pair in $users[$dept]) {
        $first = $pair[0]
        $last = $pair[1]
        $sam = ("$first.$last").ToLower()
        $upn = "$sam@corp.local"
        $ouPath = "OU=$dept,OU=CorpUsers,$domain"

        New-ADUser -Name "$first $last" `
            -GivenName $first -Surname $last `
            -SamAccountName $sam -UserPrincipalName $upn `
            -Path $ouPath -AccountPassword $defaultPassword `
            -Enabled $true -ChangePasswordAtLogon $false `
            -Department $dept

        Add-ADGroupMember -Identity "$dept-Users" -Members $sam
    }
}

# Make one IT user an IT-Admin
Add-ADGroupMember -Identity "IT-Admins" -Members "alex.nguyen"

# --- 4. Create a dedicated domain admin account (separate from built-in Administrator) ---
New-ADUser -Name "IT Admin Service" -SamAccountName "svc.itadmin" `
    -UserPrincipalName "svc.itadmin@corp.local" `
    -Path "OU=IT,OU=CorpUsers,$domain" `
    -AccountPassword $defaultPassword -Enabled $true `
    -ChangePasswordAtLogon $false
Add-ADGroupMember -Identity "Domain Admins" -Members "svc.itadmin"

# --- 5. Deliberately vulnerable accounts for later attack practice ---

# AS-REP Roastable account (no Kerberos preauth required)
New-ADUser -Name "Legacy Backup Service" -SamAccountName "svc.backup" `
    -UserPrincipalName "svc.backup@corp.local" `
    -Path "OU=IT,OU=CorpUsers,$domain" `
    -AccountPassword $defaultPassword -Enabled $true `
    -ChangePasswordAtLogon $false
Set-ADAccountControl -Identity "svc.backup" -DoesNotRequirePreAuth $true

# Kerberoastable account (SPN set, common for service accounts)
New-ADUser -Name "SQL Service Account" -SamAccountName "svc.sql" `
    -UserPrincipalName "svc.sql@corp.local" `
    -Path "OU=IT,OU=CorpUsers,$domain" `
    -AccountPassword $defaultPassword -Enabled $true `
    -ChangePasswordAtLogon $false
setspn -A MSSQLSvc/dbserver.corp.local:1433 svc.sql

Write-Host "`nDone. Created 5 OUs, 6 groups, 17 users (15 dept users + 1 admin + vulnerable service accounts)." -ForegroundColor Green
Write-Host "Default password for ALL accounts: Passw0rd123!" -ForegroundColor Yellow
