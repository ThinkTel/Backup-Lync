<#
.SYNOPSIS

A backup script for Lync that uses GIT (via libgit2) to save the data, provide diff emails of changes (similar to RANCID) and creates zip snapshots.

.DESCRIPTION

Version 1.0.1 released 2015-04-15

If you specify Commit, libgit2 is used to interact with GIT. It is used via libgit2sharp and if either of these dlls are not in the same directly as the script, they will be downloaded from NuGet.

.PARAMETER IncludeConfig 

switch to include configuration in backup (default true)

.PARAMETER IncludeUsers 

switch to include user data in backup

.PARAMETER IncludeRgs 

switch to include RGS data in backup

.PARAMETER Archive

switch to create a ZIP file of this backup run

.PARAMETER Commit

switch to commit this run into a local GIT repository

.PARAMETER CommitMessage

optional string to document this backup run for the Commit

.PARAMETER EmailArchiveTo

space or comma separated list of email addresses to email the ZIP archive to

.PARAMETER EmailChangesTo

space or comma separated list of email addresses to email the differences between this and the last commit to

.PARAMETER From

email address that the email sent by EmailArchiveTo and EmailChangesTo will be sent from

.PARAMETER SmtpServer

FQDN of the SMTP server that the email sent by EmailArchiveTo and EmailChangesTo will be sent using

.EXAMPLE

Backup Lync configuration, commit changes and email a diff (similar to RANCID)

Backup-Lync.ps1 -IncludeConfig -Commit -EmailChangesTo my.email@domain.com -From lyncbackup@domain.com -SmtpServer smtp.domain.com
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
	[Parameter(Position=0)][string]$Path = ".\data",
	[Parameter()][switch]$IncludeConfig = $true,
	[Parameter()][switch]$IncludeUsers = $false,
	[Parameter()][switch]$IncludeRgs = $false,
	[Parameter()][switch]$Archive = $true,
	[Parameter()][switch]$Commit = $true,
	[Parameter()][string]$CommitMessage,
	[Parameter()][string]$EmailArchiveTo,
	[Parameter()][string]$EmailChangesTo,
	[Parameter()][string]$From,
	[Parameter()][string]$SmtpServer
)

$start = [DateTime]::UtcNow
$thisScriptPath = [io.path]::GetDirectoryName($MyInvocation.MyCommand.Path)

if(!$From) {
	$fqdn = [System.Net.Dns]::GetHostByName($env:computerName).HostName
	$From = $env:USERNAME + "@" + $fqdn
}

[reflection.assembly]::LoadWithPartialName("windowsbase") | out-null # for system.io.packaging

if($Commit -and !$(ls $thisScriptPath\libgit2sharp.dll -ErrorAction SilentlyContinue)) {
	Write-Verbose "Commit requested but libgit2sharp.dll not found; downloading..."

	$wc = new-object System.Net.WebClient
	
	#[system.reflection.assembly]::LoadWithPartialName("system.runtime.serialization") | out-null
	#$json = new-object system.runtime.serialization.json.datacontractjsonserializer $([string[]])
	#$verStr = $wc.downloadstring("https://nuget.org/api/v2/package-versions/libgit2sharp")
	#$verData = [system.text.encoding]::ascii.getbytes($verStr)
	#$mem = new-object system.io.memorystream @(,[byte[]]$verData)
	#[string[]]$versions = $json.ReadObject($mem)
	#$latestVersion = $versions | select -last 1
	$latestVersion = "0.21.0.176"
	
	$url = "https://www.nuget.org/api/v2/package/{0}/{1}" -f "libgit2sharp",$latestVersion
	$tempNupkg = join-path $env:temp "libgit2sharp.nupkg"
	$wc.DownloadFile($url, $tempNupkg)
	$nupkg = [system.io.packaging.package]::open($tempNupkg)
	
	$dll = $nupkg.GetPart("/lib/net40/LibGit2Sharp.dll")
	$file = new-object System.IO.FileStream $(Join-Path $thisScriptPath "libgit2sharp.dll"), "Create"
	$dll.GetStream().CopyTo($file)
	
	$dll = $nupkg.getparts() | where { $_.Uri -match "amd64/git2-.*\.dll" }
	$git2Dll = $dll.Uri.ToString() -split '/' | select -last 1
	$file = new-object System.IO.FileStream $(Join-Path $thisScriptPath $git2Dll), "Create"
	$dll.GetStream().CopyTo($file)
	$file.Close()
}

if($EmailArchiveTo -and (!$From -or !$SmtpServer)) {
	Write-Error "From and SmtpServer are required for EmailArchiveTo"
	exit
}

if($EmailChangesTo -and (!$From -or !$SmtpServer)) {
	Write-Error "From and SmtpServer are required for EmailChangesTo"
	exit
}

Import-Module Lync -ErrorAction Stop -Verbose:$false
[reflection.assembly]::LoadWithPartialName("system.xml.linq") | out-null

if($Path.StartsWith(".")) {
	$Path = join-path $thisScriptPath $Path.Substring(2)
}

$arkPath = join-path $Path "archive"
$bakPath = join-path $Path "current"
if(-not $(Test-Path $bakPath)) {
	mkdir $bakPath | out-null
}

if($IncludeConfig) {
	## BACKUP TOPOLOGY
	Write-Verbose "Backing up topology"
	(Get-CsTopology -AsXml).ToString() | Out-File $bakPath\Topology.xml -encoding ascii

	## BACKUP CONFIG & POLICIES
	if(Test-Path $bakPath\config) {
		rm $bakPath\config -recurse
	}
	mkdir $bakPath\config | Out-Null

	$ExcludedCommands = @('Get-CsEffectivePolicy', 'Get-CsRgsConfiguration', 'Get-CsWatcherNodeConfiguration')
	$cmds = @("Get-CsDialPlan","Get-CsVoiceRoute","Get-CsPstnUsage","Get-CsDialInConferencingAccessNumber","Get-CsExUmContact")
	$cmds += Get-Command Get-Cs*Configuration,Get-Cs*Policy -Module Lync | %{ $_.Name } | ?{ $ExcludedCommands -notcontains $_ } 

	$cmds | foreach {
		$type = $_.Substring(6) 

		Write-Verbose "Backing up $type"
		[array]$ret = & $_ -Verbose:$false 
		if($ret) {
			## don't have results with .element
			# Get-CsDialInConferencingAccessNumber
			# Get-CsExUmContact
			# Get-CsAccessEdgeConfiguration
			
			## in addition, some that have .element don't have .anchor (but they have identity)
			# Get-CsVoiceRoute
			# Get-CsHealthMonitoringConfiguration
			
			if($ret[0].Element) {
				mkdir "$bakPath\config\$type" | out-null
				
				# write one per file identified by anchor (if available) or identity otherwise
				$ret | foreach {
					if($_.Anchor) {
						if($_.Identity -eq "Global") {
							$id = $_.Identity
						} else {
							$id = $($_.Anchor.FullName -replace ":","_") + "_" + $_.Anchor.TagId
						}
					} else {
						$id = $_.Identity
					}
					$_.Element.ToString() | out-file "$bakPath\config\$type\$($id).xml" -encoding ascii
				}
			} elseif($ret[0].LineUri) { # exumcontact & dialinconferencingaccessnumber
				mkdir "$bakPath\config\$type" | out-null
				
				$ret | foreach {
					$id = $_.LineUri.Substring(4)
					$_ | Export-Clixml -Path "$bakPath\config\$type\$($id).xml" -encoding ascii
				}
			} else {
				$ret | Export-Clixml -Path "$bakPath\config\$($type).xml" -encoding ascii
			}
		}
	}
}

if($IncludeUsers) {
	## BACKUP USER DATA
	if(Test-Path $bakPath\users) {
		# by removing this path we don't have to prune it later for users who may be gone
		# and since git will detect changes; if the generated files are the same then it won't be included in the commit
		rm $bakPath\users -Recurse
	}
	mkdir $bakPath\users | Out-Null

	if(Test-Path $bakPath\userdata) {
		rm $bakPath\userdata -Recurse
	}
	mkdir $bakPath\userdata | Out-Null

	$settings = new-object system.xml.XmlWriterSettings
	$settings.Indent = $true;
	$settings.IndentChars = "  ";
	$settings.OmitXmlDeclaration = $false;

	# in case there's a mixed environment
	$supportedPools = Get-CsService -UserServer | ?{ $_.Version -eq 6 } | %{ $_.PoolFqdn } | sort -Unique 

	$users = Get-CsUser | sort SipAddress
	foreach($u in $users) {
		$sip = $u.SipAddress.Substring(4)
		Write-Verbose "Backing up user $sip"
		$u | Export-Clixml -Path "$bakPath\users\$($sip).xml" -encoding ascii
		if($supportedPools -notcontains $u.RegistrarPool) {
			Write-Warning "$sip is not on a supported pool"
		} else {
			$tempZip = [io.path]::GetTempFileName()
			rm $tempZip
			Export-CsUserData -PoolFqdn $u.RegistrarPool.ToString() -UserFilter $sip -FileName $tempZip -Verbose:$false
			$pkg = [system.io.packaging.package]::open($tempZip)
			$zip = $pkg.GetPart("/DocItemSet.xml").GetStream()

			# this indents the file nicely so that we have better diffs
			[system.xml.linq.xdocument]::Load($zip).ToString() | Out-File "$bakPath\userdata\$($sip).xml" -encoding ascii
			
			$pkg.Close()
			rm $tempZip
		}
	}
}

## TODO: backup the conferencing directory's (and their export-csuserdata -confdirectoryfilter data too)

if($IncludeRgs) {
	## BACKUP RGS
	# TODO: maybe we can export-clixml the rgs workflow/queue/agentgroup/holidayset/hoursofbusiness objects?
	# if(-not $(Test-Path $bakPath\rgs)) {
		# mkdir $bakPath\rgs | Out-Null
	# }

	get-csservice -applicationserver | ?{ $_.version -eq 6 } | %{ $_.identity } | sort -unique | foreach {
		$name = $_ -split ':' | select -first 1 -skip 1
		export-csrgsconfiguration -source "service:$_" -filename "$bakPath\rgs_$($name).zip"
	}
}

function Email($to, $subjTplt, $attachment, $mimetype) {
	$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
	$subj = $subjTplt -f $domain,$Script:start

	$msg = new-object System.Net.Mail.MailMessage
	$msg.From = $Script:From
	$atLeastOne = $false
	$to -split '[\s,]+' | foreach {
		$addr = $_.Trim()
		if($addr) {
			try {
				$msg.To.Add($addr)
				$atLeastOne = $true
			} catch {
				Write-Error "Failed to add $addr as 'To' address for email '$subjTplt': $_"
			}
		}
	}

	$msg.Subject = $subj
	if($([System.Net.Mime.MediaTypeNames+Text]::Plain) -eq $mimetype) {
		$msg.Body = gc $attachment -raw
	} else {
		$msg.Body = "See attached file"
		$msgAttachment = new-object System.Net.Mail.Attachment $attachment, $mimetype
		$msgAttachment.ContentDisposition.FileName = $domain + "_" + $date + ".zip"
		$msgAttachment.ContentDisposition.CreationDate = [System.IO.File]::GetCreationTime($attachment)
		$msgAttachment.ContentDisposition.ModificationDate = [System.IO.File]::GetLastWriteTime($attachment)
		$msgAttachment.ContentDisposition.ReadDate = [System.IO.File]::GetLastAccessTime($attachment)
		$msg.Attachments.Add($msgAttachment)
	}

	# TODO: instead of $SmtpServer we could MX lookup instead
	# SEE: http://blog.icewolf.ch/archive/2013/05/27/powershell-dns-reverse-and-mx-lookup.aspx
	if($atLeastOne) {
		$smtp = new-object System.Net.Mail.SmtpClient $SmtpServer
		$smtp.Send($msg)
	} else {
		Write-Warning "Not sending email '$subjTplt' since there are not valid 'To' email addresses"
	}
}

## ARCHIVE ALL DATA INTO DATE STAMPED FILE
if($Archive) {
	if(-not $(Test-Path $arkPath)) {
		mkdir $arkPath | out-null
	}
	$arkFile = "$arkPath\{0:yyyMMdd}.zip" -f $start
	if(Test-Path $arkFile) {
		rm $arkFile
	}

	$compression = [system.io.packaging.compressionoption]::Maximum
	
	Write-Verbose "Creating archive $arkFile"
	$zip = [system.io.packaging.package]::open($arkFile, [system.io.filemode]::Create)
	
	ls $bakPath\**.xml -recurse | foreach {
		$item = $_.FullName.Substring($bakPath.Length) -replace '\\','/'
		Write-Verbose "Archiving $item"
		# a part name can't have a space (per the Open Packaging Conventions specification) so replace those
		$item = $item -replace ' ','_' -replace '#',''
		try {
			$part = $zip.CreatePart($item, "text/xml", $compression)
			$file = new-object system.io.filestream $_.FullName, $([system.io.filemode]::open), $([system.io.fileaccess]::Read)
			$file.CopyTo($part.GetStream())
			$file.Close()
		} catch {
			Write-Error "Failed to create part $item; $_"
		}
	}
	
	$zip.Close()
	
	if($EmailArchiveTo) {
		Write-Verbose "Emailing archive $arkFile to $EmailArchiveTo"
		Email $EmailArchiveTo "Lync Backup for {0} ({1:yyyy-MMM-dd})" $arkFile $([System.Net.Mime.MediaTypeNames+Application]::Zip)
	}

	# TODO: optionally only keep a certain number of backups
}

## COMMIT ALL CHANGES
if($Commit) {
	Import-Module $thisScriptPath\libgit2sharp.dll -ErrorAction Stop -Verbose:$false

	if(-not $(Test-Path $bakPath\.git)) {
		Write-Verbose "Initializing git repo"
		[LibGit2Sharp.Repository]::Init($bakPath) | out-null
		"*.zip" | Out-File $bakPath\.gitignore -encoding ascii
	}

	$git = new-object LibGit2Sharp.Repository "$bakPath\.git"
	$dirty = $false
	$statusOpts = new-object LibGit2Sharp.StatusOptions
	$stageOpts = new-object LibGit2Sharp.StageOptions
	$git.RetrieveStatus($statusOpts) | foreach {
		if($_.State -eq "Untracked" -or $_.State -eq "Missing" -or $_.State -eq "Modified") {
			Write-Verbose "Staging $($_.FilePath)"
			$git.Stage($_.FilePath, $stageOpts)
			$dirty = $true
		} else {
			Write-Verbose "Skipping $($_.FilePath) [$($_.State)]"
		}
	}
	if($dirty) {
		Write-Verbose "Recording changes..."
		$diffPath = join-path $Path "changes"
		if(-not $(Test-Path $diffPath)) {
			mkdir $diffPath | out-null
		}
		
		$diffFile = "$diffPath\{0:yyyy-MM-dd_HHmm}.txt" -f $start
		$compare = $git.diff.gettype().getmethod("Compare", [type[]]@([LibGit2Sharp.Tree], [LibGit2Sharp.DiffTargets], [System.Collections.Generic.IEnumerable[string]], [LibGit2Sharp.ExplicitPathsOptions], [LibGit2Sharp.CompareOptions]))
		$compareTree = $compare.MakeGenericMethod([libgit2sharp.patch])
		# $co = new-object libgit2sharp.compareoptions
		# $co.ContextLines = 0
		$diff = $compareTree.Invoke($git.Diff, @($git.Head.Tip.Tree, [libgit2sharp.difftargets]::Index, $null, $null, $null))
		$diff | foreach { 
			if($_.Status -eq "Added") {
				"diff added " + $($_.Path -Replace '\\','/') + "`r`n"
			} elseif($_.Status -eq "Removed") {
				"diff removed " + $($_.OldPath -Replace '\\','/') + "`r`n"
			} else {
				$_.Patch -Replace "`r?`n","`r`n"
			}
		} | Out-File $diffFile -encoding ascii

		if($EmailChangesTo) {
			Write-Verbose "Emailing changes $diffFile to $EmailChangesTo"
			Email $EmailChangesTo "Lync config changes for {0} ({1:yyyy-MMM-dd HH:mm})" $diffFile $([System.Net.Mime.MediaTypeNames+Text]::Plain)
		}
		
		Write-Verbose "Committing..."
		$sig = new-object libgit2sharp.signature "Backup-Lync.ps1",$From,$([DateTimeOffset]::Now)
		if($CommitMessage) {
			$msg = $CommitMessage
		} else {
			$msg = "Backup run @ {0:yyyy-MM-dd HH:mm} UTC" -f $start
		}
		$commitOpts = new-object LibGit2Sharp.CommitOptions
		$git.Commit($msg, $sig, $sig, $commitOpts) | out-null
	}
	
	# TODO: add option to push to remote (eg origin)
	# $pushResult = $git.Network.Push($git.Remotes["origin"], "HEAD", "refs/heads/destination_branch");
	# if ($pushResult.HasErrors)
	# {
		# $errMsg = $(pushResult.FailedPushUpdates | %{ "`t{0} : {1}" -f $_.Reference,$_.Message }) -join "`r`n"
		# Write-Error "Errors while pushing commit:`r`n$errMsg"
	# }
}
