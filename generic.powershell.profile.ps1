##############################
# Generic PowerShell Profile #
##############################

# T3XT ALIASES

# GENERAL PC INFO ALIASES

## GET PS VERSION INFO

$psvt=$PSVersionTable
$pvtv=$PSVersionTable.PSVersion
Function psversion {Write-Output $pvtv}
Function psv {Write-Output $pvtv}

## GET PC/WINDOWS VERSION INFO

# $computerinfo=(Get-ComputerInfo)
function Get-CompInfo () {
	if (!$computerinfo) { 
		Set-Variable -Name computerinfo -Visibility Public -Value (Get-ComputerInfo) -Scope Global
	}; 
		# Write-Output "Windows Product Name: $($computerinfo.WindowsProductName)`nWindows Version     : $($computerinfo.WindowsVersion)"
}
function Get-PCInfo () { if (!$computerinfo) { $env:computerinfo = (Get-ComputerInfo) } }
# if (!$computerinfo) { Set-Variable -Name computerinfo -Visibility Public -Value (Get-ComputerInfo) }
Function release {if (!$computerinfo) { Set-Variable -Name computerinfo -Visibility Public -Value (Get-ComputerInfo) -Scope Global }; Write-Output "Windows Product Name: $($computerinfo.WindowsProductName)`nWindows Version     : $($computerinfo.WindowsVersion)"}
Function osrelease {if (!$computerinfo) { Set-Variable -Name computerinfo -Visibility Public -Value (Get-ComputerInfo) -Scope Global }; Write-Output "Windows Product Name: $($computerinfo.WindowsProductName)`nWindows Version     : $($computerinfo.WindowsVersion)"}
Function osversion {if (!$computerinfo) { Set-Variable -Name computerinfo -Visibility Public -Value (Get-ComputerInfo) -Scope Global }; Write-Output "Os Name        : $($computerinfo.OsName)`nOs Version     : $($computerinfo.OsVersion)`nOs Build Number: $($computerinfo.OsBuildNumber)"}
# Function uname {Write-Output "$($computerinfo.OsHardwareAbstractionLayer) : $($computerinfo.WindowsBuildLabEx)"}
Function uname {
	param ([switch] $a)
	if (!$computerinfo) { Set-Variable -Name computerinfo -Visibility Public -Value (Get-ComputerInfo) }; 
	if ($a -eq $true)
	{
	    Write-Output "Windows Product Name  : $($computerinfo.WindowsProductName)`nWindows Version        : $($computerinfo.WindowsVersion)`nOs Name                : $($computerinfo.OsName)`nOs Version             : $($computerinfo.OsVersion)`nOs Build Number        : $($computerinfo.OsBuildNumber)`nFull Build Information : $($computerinfo.OsHardwareAbstractionLayer) : $($computerinfo.WindowsBuildLabEx)"
	}
	else
	{
	    Write-Output "$($computerinfo.OsHardwareAbstractionLayer) : $($computerinfo.WindowsBuildLabEx)"
	}
}

Function Get-IP4 {Ipconfig | sls IPv4}
	New-Alias IP Get-IP4

# Function Get-ErrorsPerDay { Get-EventLog -LogName 'Application' -EntryType Error -After ((Get-Date).Date.AddDays(-30))| ForEach-Object{$_|Add-Member -	MemberType NoteProperty -Name LogDay -Value $_.TimeGenerated.ToString("yyyyMMdd") -PassThru} | Group-Object LogDay | Select-Object @{N='LogDay';E=	{[int]$_.Name}},Count | Sort-Object LogDay | Format-Table –Auto}
Function Get-ErrorsPerDay { Get-EventLog -LogName 'Application' -EntryType Error -After ((Get-Date).Date.AddDays(-30))| ForEach-Object{$_|Add-Member -	MemberType NoteProperty -Name LogDay -Value $_.TimeGenerated.ToString("yyyyMMdd") -PassThru} | Group-Object LogDay | Select-Object @{N='LogDay';E=	{[int]$_.Name}},Count | Sort-Object LogDay | Format-Table }
	New-alias GDE Get-ErrorsPerDay

Function Get-BootTime {wmic OS get LastBootupTime}
	New-Alias GBT Get-BootTime

Function Get-Version {$psversiontable}
	New-Alias ver Get-Version

Function Get-SerialNumber {(Get-WmiObject -Class:Win32_BIOS).SerialNumber}
	New-Alias GSer Get-SerialNumber	
	
Function Get-Model {(Get-WmiObject -Class:Win32_ComputerSystem).Model}
	New-Alias GML Get-Model
  
 ## GET POWERSHELL MODULE INFO
 
 # List-Mods ??
function Show-Mods {
	param (
		[string]$type # OptionalParameters #could also replace with (3) boolean(s) with a default of false -im -la -all
	)
	if ([string]::IsNullOrEmpty($type)) {
		Write-Output "===========================`nGet Installed Modules`n===========================";
		Get-InstalledModule | Format-Table -AutoSize;
		Write-Output "===========================`nGet Available Modules`n===========================";
		Get-Module -ListAvailable | Format-Table -AutoSize;
	}
	# elseif ($type -ilike "*IM|In*") {
	elseif ($type -imatch 'IM|I\w*') {
		Write-Output "===========================`nGet Installed Modules`n===========================";
		Get-InstalledModule | Format-Table -AutoSize;
	}
	# elseif ($type -ilike "*LA|Li*") {
	elseif ($type -imatch 'LA|L\w*') {
		Write-Output "===========================`nGet Available Modules`n===========================";
		Get-Module -ListAvailable | Format-Table -AutoSize;
	}
}
Set-Alias -Name Get-Mods -Value 'Show-Mods'
function Show-Commands {
	param ($param1)
	$modname = (show-mods | Where-Object {$_.name -like "*$param1*"} ).Value;
	import-module $modname
	# (get-module $modname).ExportedCommands
	Get-Command -Module $modname
  }
  
## FIND FILE LOCATION

Function whereis {
	param ($param1)
	cmd /c where $param1
	# where.exe $param1
}
Function fwhere {
	param ($param1)
	where.exe $param1
}
Function cwhere {
	param ($param1)
	cmd /c where $param1
}
Function which {
	param ($param1)
	(get-command $param1).path
}
Function fwhich {
	param ($param1)
	(get-command $param1).path
}
# Function locate 
New-Alias -Name awhich -Value 'get-command' # 'where.exe' # C:\WINDOWS\system32\where.exe
New-Alias -Name gwhich -Value 'get-command'
New-Alias -Name ewhich -Value 'where.exe' # wwhich? ; C:\WINDOWS\system32\where.exe
# New-Alias -Name cwhich -Value 'cmd /c where' ## DIDN'T WORK

## GET FILE VERSION AND FILE SIZE INFO

### FILE VERSION

Function show-fileversion {
	param ($param1)
	# $filelocation=(get-command $param1).path
	# (Get-Item $filelocation).VersionInfo
	## ^^WORKS ^^
	(Get-Item (Get-Command $param1).path).VersionInfo | Format-Table -auto
	
}
Function show-registry-version {
	param ($param1)
	$ms1=(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -like "*$param1*"})
	$ms2=(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -like "*$param1*"})
	$ms3=(Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -like "*$param1*"})
	if ($ms1) {
	# Write-Output "ms1: $ms1`nDisplay Name: $($ms1.DisplayName)`nDisplay Version: $($ms1.DisplayVersion)"
	Write-Output "---`nms1`n---`nDisplay Name: $($ms1.DisplayName)`nDisplay Version: $($ms1.DisplayVersion)"
	}
	if ($ms2) {
	# Write-Output "ms2: $ms2`nDisplay Name: $($ms2.DisplayName)`nDisplay Version: $($ms2.DisplayVersion)"
	Write-Output "---`nms2`n---`nDisplay Name: $($ms2.DisplayName)`nDisplay Version: $($ms2.DisplayVersion)"
	}
	if ($ms3) {
	# Write-Output "ms3: $ms3`nDisplay Name: $($ms3.DisplayName)`nDisplay Version: $($ms3.DisplayVersion)"
	Write-Output "---`nms3`n---`nDisplay Name: $($ms3.DisplayName)`nDisplay Version: $($ms3.DisplayVersion)"
	}
}

# $ms1=(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -like "*$ptest1*"})
# $ms2=(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -like "*$ptest1*"})
# $ms3=(Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -like "*$ptest1*"})

### FILESIZE

# You can then pipe the output of Get-ChildItem through Select-Object and use a calculated property to format the filesize:
# Get-ChildItem | Select-Object Name, @{Name="Size";Expression={Format-FileSize($_.Length)}}
# The function could of course be improved to account for sizes in the PB range and more, or to vary the number of decimal points as necessary.
Function Format-FileSize() {
    Param ([int64]$size)
    If     ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
    ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
    ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
    ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
    ElseIf ($size -gt 0)   {[string]::Format("{0:0.00} B", $size)}
    Else                   {""}
}
Update-TypeData -TypeName System.IO.FileInfo -MemberName FileSize -MemberType ScriptProperty -Value { 
    switch($this.length) {
               { $_ -gt 1tb } 
                      { "{0:n2} TB" -f ($_ / 1tb) }
               { $_ -gt 1gb } 
                      { "{0:n2} GB" -f ($_ / 1gb) }
               { $_ -gt 1mb } 
                      { "{0:n2} MB " -f ($_ / 1mb) }
               { $_ -gt 1kb } 
                      { "{0:n2} KB " -f ($_ / 1Kb) }
               default  
                      { "{0} B " -f $_} 
             }      
    } -DefaultDisplayPropertySet Mode,LastWriteTime,FileSize,Name
## ll chro* | Show-FileSize
Function Show-FileSize() {
	# Param($data)
	$input | Select-Object Mode, LastWriteTime, @{Name="Size";Expression={Format-FileSize($_.Length)}}, Name
}
## Get-FileSize chr*
Function Get-FileSize() {
	Param($data)
	Get-Childitem $data | Select-Object Mode, LastWriteTime, @{Name="Size";Expression={Format-FileSize($_.Length)}}, Name
}
# ll chr* | Find-FileSize ||OR|| Find-FileSize chr*
Function Find-FileSize() {
	Param($data)
	if ($input) {
		$input | select  Mode, LastWriteTime, Name, FileSize, Length, @{Name="Size";Expression={Format-FileSize($_.Length)}}
	} 
	if ($data) {
		Get-ChildItem $data | select  Mode, LastWriteTime, Name, FileSize, Length, @{Name="Size";Expression={Format-FileSize($_.Length)}}
	}
}
# Same instructions as Find-FileSize
Function Update-FileSize() {
	Param($data)
	if ($input) {
		$input | select Name,FileSize,length
	} 
	if ($data) {
		Get-ChildItem $data | select Name,FileSize,length
	}
}

## BACKUP COMMAND HISTORY

Function bak {
	$Username=(whoami).Split("\")[1];
	$Today=Get-Date -Format "yyyy_MMM_dd";
	$Hostname=hostname;
	$Folderpath = "C:\Users\$Username\Documents\$Hostname-PS-History";
	$PShistpath = (Get-ChildItem .\Documents\ -Recurse | where {$_.PSIsContainer -eq $true -and $_.Name -like "PS-History"}).PSPath.SPlit("::")[1]
	
	Write-Host "Current PS History Path: $PShistpath";

	try {
		if (-not(Test-Path -Path $Folderpath -PathType Container)) {
			$null = New-Item -ItemType Directory -Path $archiveFolder -ErrorAction STOP
			Write-Host "Directory [$Hostname-PS-History] has been created"
		}
	} catch {
		throw $_.Exception.Message
	}
	 
	if ($PSVersionTable.PSVersion.Major -eq 7) {
		Get-Content (Get-PSReadLineOption).HistorySavePath | Format-Custom >> C:\Users\${Username}\Documents\${Hostname}-PS-History\ps_7.x_history_backup_${Today}.out
	}
	if ($PSVersionTable.PSVersion.Major -eq 5) {
		Get-Content (Get-PSReadLineOption).HistorySavePath | Format-Custom >> C:\Users\${Username}\Documents\${Hostname}-PS-History\ps_5.x_history_backup_${Today}.out
	}
}


function qbak {
	$Username=(whoami).Split("\")[1]; 
	$Today=Get-Date -Format "yyyy_MMM_dd"; 
	$Hostname=hostname;
	# $Folderpath = "C:\Users\$Username\Documents\$Hostname-PS-History";
	if ($PSVersionTable.PSVersion.Major -eq 7) {
		Get-Content (Get-PSReadLineOption).HistorySavePath | Format-Custom >> C:\Users\${Username}\Documents\${Hostname}-PS-History\ps_7.x_history_backup_${Today}.out
	}
	if ($PSVersionTable.PSVersion.Major -eq 5) {
		Get-Content (Get-PSReadLineOption).HistorySavePath | Format-Custom >> C:\Users\${Username}\Documents\${Hostname}-PS-History\ps_5.x_history_backup_${Today}.out
	}
}

## OTHER FUNCTIONS

Function show-startup-programs {
	Write-Output "WMIC";
	wmic startup get caption,command;
	Write-Output "Get-CimInstance"
	Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location | Out-GridView
}
# List-Functions; List-MyFunctions; Get-MyCommands
function List-Functions () {
	alias;
	Get-ChildItem function:\
}
function vscode() { 
  $Username=(whoami).Split("\")[1];
  cmd /c "C:\Users\$Username\AppData\Local\Programs\Microsoft VS Code\bin\code" $Args; 
 };
New-Alias -Name code -Value 'vscode'

function get-path () { $env:path -split ";" };
Set-Alias -Name env -Value 'Get-ChildItem -Path Env:';

Set-Alias -Name ll -Value 'Get-ChildItem';
# Set-Alias -Name ... -Value 'Set-Location ..';

function .. { Set-Location ..; };

## GENERATE LOG NAMES

Set-Alias -Name Log-Date -Value 'get-date -UFormat %Y.%m.%d-%H.%M.%S_%Z.';
function Get-Log-Date () { 
	Param(
	[Parameter(Mandatory=$false)]
	[string[]]
	$logName
	)
	if (!$logName) {
		get-date -UFormat %Y.%m.%d-%H.%M.%S_%Z. ; 
	}
	else {
		get-date -UFormat %Y.%m.%d-%H.%M.%S_%Z.$logName.;
	}
		
}
function Get-Named-Log-Date () {
	Param(
	[Parameter(Mandatory=$false)]
	[string[]]
	$logName = "$(hostname)"
	)
	Write-Output "$(get-date -UFormat %Y.%m.%d-%H.%M.%S_%Z.)$logName.";
}
function Get-Custom-Log-Name () {
	Param(
		[Parameter(Mandatory=$false)]
		[string[]]
		$logName
		)
	if ($logName) { ## using if ($logName) instead of if ($Args)
		Write-Output "$(get-date -UFormat %Y.%m.%d-%H.%M.%S_%Z.)$logName.";
	} else {
		Write-Output "$(get-date -UFormat %Y.%m.%d-%H.%M.%S_%Z.)PowerShell.$MajorA.$MinorA.";
	}
}
Set-Alias -Name Log-Date -Value 'Get-Log-Date'
Set-Alias -Name Named-Log-Date -Value 'Get-Named-Log-Date'
Set-Alias -Name Name-Log -Value 'Get-Named-Log-Date'

## SESSION AND TRANSCRIPT INFO

# Create the PS Sessions Transcript Folder
try {
    if (-not(Test-Path -Path "$HOME\Documents\PowerShellSessions" -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $archiveFolder -ErrorAction STOP
        Write-Host "Directory [PowerShellSessions] has been created"
    }
} catch {
    throw $_.Exception.Message
}

# Create the PS-History Folder
try {
    $Username=(whoami).Split("\")[1];
    $Hostname=hostname;
    $Folderpath = "C:\Users\$Username\Documents\$Hostname-PS-History";
    if (-not(Test-Path -Path $Folderpath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $archiveFolder -ErrorAction STOP
        Write-Host "Directory [$Hostname-PS-History] has been created"
    }
} catch {
    throw $_.Exception.Message
}

Function e { qbak; Stop-Transcript; exit; }
Set-Alias -Name exit -value 'Stop-Transcript; exit';
$MajorA=$PSVersionTable.PSVersion.Major;
$MajorB=$pvtv.Major;
$MinorA=$PSVersionTable.PSVersion.Minor;
$MinorB=$pvtv.Minor;
$LaDate=Get-Date -Format "yyyy.MM.dd_HH.mm.ss";
Start-Transcript -Path ${HOME}\Documents\PowerShellSessions\PS_Session_${MajorA}.${MinorA}_${LaDate}_Transcript.out;
# BOTTOM OF PROFILE

