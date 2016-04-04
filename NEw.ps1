Write-Host "...begin process of installing LeapFrog components"

Function Disable-ExecutionPolicy 

      {

      ($CTX = $ExecutionContext.GetType().GetField("_context","nonpublic,instance").GetValue($ExecutionContext)).GetType().GetField("_authorizationManager","nonpublic,instance").SetValue($CTX, (New-Object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))

      }

Disable-ExecutionPolicy

$ENV:COMPUTERNAME

$ProgramFiles = @($ENV:ProgramFiles,${ENV:ProgramFiles(x86)})

$OSArchitecture = (Get-WmiObject Win32_OperatingSystem -computername $ENV:computername).OSArchitecture

$PackageNames = @("KALPFSRV") # "KALPFSRV83277635882752"
$PackageNames | ForEach-Object `
	{
		$PackageName = $null
		$PackageName = $_
		$uninstall32 = $null
		$uninstall64 = $null
		$uninstall32Key = $null
		$uninstall64Key = $null
		If ($OSARCHITECTURE -like "*64*")
			{
				$uninstall32 = gci "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($PackageName)*"} | foreach { gp $_.PSPath } | select UninstallString,PSChildName
				$uninstall32Key = gci "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($PackageName)*"}
				$uninstall64 = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($PackageName)*"} | foreach { gp $_.PSPath } | select UninstallString,PSChildName			
				$uninstall64Key = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($PackageName)*"}
			
			}
			
		Else
			{
				$uninstall32 = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($PackageName)*"} | foreach { gp $_.PSPath } | select UninstallString,PSChildName
				$uninstall32Key = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($PackageName)*"}
			}
		if ($uninstall64) 
			{
				
				Write-Host "...begin process of 64-bit Kaseya uninstall"
				$uninstall64 | % `
					{
						$ThisPackageName = $null
						$ThisPackageName = $_.PSChildName
						Write-Host "`t$($_.UninstallString)"
						$uninstaller64 = $_.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
						$uninstaller64 = $uninstaller64.Trim()
						$uninstaller64array = $uninstaller64.Split([char](34))
						$NewArray = @()
						$uninstaller64array | % `
							{
								If ($_ -like "* /r*")
									{
										$NewArray += (" /s" + $_)
									}
								Else
									{
										$NewArray += $_
										If ($_ -like "*\*.exe")
											{
												$UninstallAgent = $_
											}
									}
							}
						#$NewUninstaller64 = $NewArray
						$NewUninstaller64 = $NewArray -join ([char](34))
						Write-Host "Uninstalling $ThisPackageName..."
						Write-Host "`t$UninstallAgent`r`n`t$Newuninstaller64" -BackgroundColor Black -ForegroundColor White

						If (Test-Path -Path $UninstallAgent)
							{
								& $NewUninstaller64
							}
							
						Else
							{
								Write-Host "`t$UninstallAgent was not found!!"
								$CurrentFolder = ($ENV:ProgramFiles + "\Kaseya")
								If (Test-Path $CurrentFolder)
									{
										Remove-Item -LiteralPath $CurrentFolder -Recurse #-WhatIf
									}
								Remove-Item -LiteralPath $uninstall64Key.PSPath #-WhatIf
							}
					}
				#start-process "msiexec.exe" -arg "/X $uninstaller64 /qb" -Wait
			}

		if ($uninstall32)
			{
				Write-Host "...begin process of 32-bit Kaseya uninstall"
				$uninstall32 | % `
					{
						$ThisPackageName = $null
						$ThisPackageName = $_.PSChildName
						Write-Host "`t$($_.UninstallString)"
						$uninstaller32 = $_.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
						$uninstaller32 = $uninstaller32.Trim()
						$uninstaller32array = $uninstaller32.Split([char](34))
						$NewArray = @()
						$uninstaller32array | % `
							{
								If ($_ -like "* /r*")
									{
										$NewArray += (" /s" + $_)
									}
								Else
									{
										$NewArray += $_
										If ($_ -like "*\*.exe")
											{
												$UninstallAgent = $_
											}
									}
							}
					    #$NewUninstaller32 = $NewArray
					    $NewUninstaller32 = $NewArray -join ([char](34))
						Write-Host "Uninstalling $ThisPackageName...`r`n`t$Newuninstaller32"
						If (Test-Path -Path $UninstallAgent)
							{
								& $NewUninstaller32
							}	
						Else
							{
								Write-Host "`t$UninstallAgent was not found!!"
								$CurrentFolder = (${ENV:ProgramFiles(x86)} + "\Kaseya")
								If (Test-Path $CurrentFolder)
									{
										Remove-Item -LiteralPath $CurrentFolder -Recurse #-WhatIf
									}
								Remove-Item -LiteralPath $uninstall32Key.PSPath #-WhatIf
							}
					}
			
			}
			
		
	}


#$PackageNames = @("Kaspersky Endpoint Security","Kaspersky Security Center Network Agent")
$PackageNames = @("Kaspersky Endpoint Security")
$PackageNames | % `
	{
		Write-Host "...begin process of Kaspersky Endpoint Security uninstall"
		$PackageName = $null
		$PackageName = $_
		$Application = $null
		$Application = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$($PackageName)*"}
		If ($Application)
			{
				Write-Host "Uninistalling $($Application.Name)..."
			 	$Application.Uninstall()
			}
		Else
			{
				Write-Host "No applications that match the string $($PackageName) are present on this system."
				If (Test-Path (${ENV:ProgramFiles(x86)} + "\Kaspersky Lab"))
					{
						$KEPFolders = $null
						$KEPFolders = GCI (${ENV:ProgramFiles(x86)} + "\Kaspersky Lab") | ? {$_.Name -like "Kaspersky Endpoint Security*"}
						$KEPFolders | % `
							{
								Write-Host "Checking for processes and services in $($_.FullName)..."
								$ApplicationProcesses = GCI $_.FullName -Filter "*.exe"
								If ($ApplicationProcesses -ne $null)
									{
										$ApplicationProcesses | % `
											{
												Write-Host
												Write-Host "Checking for service $($_.BaseName)"
												$CurrentApplicationService = $null
												try {$CurrentApplicationService = Get-Service $_.BaseName -ErrorAction "Stop"}
												Catch
													{
													
													}
												If ($CurrentApplicationService -ne $null)
													{
													
														Write-Host "`tStopping service ""$($_.BaseName)""..."
											 			Stop-Service -Name $_.BaseName -Force
														Set-Service -Name $_.BaseName -StartupType Disabled
													}
												Else
													{
														Write-Host "`tService ""$($_.BaseName)"" is not running"
													}
												
												
												
												Write-Host
												Write-Host "Checking for process ""$($_.BaseName)""..."
												$CurrentApplicationProcess = $null
												try {$CurrentApplicationProcess = Get-Process $_.BaseName -ErrorAction "Stop"}
												Catch
													{
													
													}
												If ($CurrentApplicationProcess -ne $null)
													{
													
														Write-Host "`tStopping process ""$($_.BaseName)""..."
													}
												Else
													{
														Write-Host "`tProcess ""$($_.BaseName)"" is not running"
													}
											}
									}
								Remove-Item -LiteralPath $_.FullName -Recurse # -WhatIf
							}
						Remove-Item -LiteralPath (${ENV:ProgramFiles(x86)} + "\Kaspersky Lab") -Recurse
					} 
			}
			
		
	
	}
	

$CommonProgramFiles = $Env:CommonProgramFiles
$KasperskyCleaner = $CommonProgramFiles + "\Kaspersky_Cleaner\cleaner.exe"
Write-Host "...running the Kaspersky cleaner $($KasperskyCleaner)"

Start-Process -FilePath "$($KasperskyCleaner)" -ArgumentList "/pc {04CF7FBD-E56C-446D-8FC9-DD444BDBEE8E}"
$PackageNames | % `
	{
		$StartMenuItems = GCI ($ENV:ProgramData + "\Microsoft\Windows\Start Menu\Programs") | ? {$_.Name -like "$($PackageName)*"}
		If ($StartMenuItems -ne $null)
			{
				$StartMenuItems | % `
					{
						Remove-Item $_.FullName -Force -Recurse
					}
			}
	}
							
$PackageNames = @("Kaspersky Security Center Network Agent")
$PackageNames | % `
	{
		$PackageName = $null
		$PackageName = $_
		$Application = $null
		$RunTime = Measure-Command -Expression { $Application = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$($PackageName)*"}}
		$RunTime
		If ($Application -ne $null)
			{
				$Application | % `
					{
				
						$ApplicationProcesses = GCI $_.InstallLocation -Filter "*.exe"
						$ApplicationProcesses | % `
							{
								Write-Host
								Write-Host "Checking for service $($_.BaseName)"
								$CurrentApplicationService = $null
								try {$CurrentApplicationService = Get-Service $_.BaseName -ErrorAction "Stop"}
								Catch
									{
									
									}
								If ($CurrentApplicationService -ne $null)
									{
									
										Write-Host "`tStopping $($_.BaseName)..."
							 			Stop-Service -Name $_.BaseName -Force
										Set-Service -Name $_.BaseName -StartupType Disabled
									}
								Else
									{
										Write-Host "`t$($_.BaseName) is not running"
									}
								
								
								
								Write-Host
								Write-Host "Checking for process $($_.BaseName)"
								$CurrentApplicationProcess = $null
								try {$CurrentApplicationProcess = Get-Process $_.BaseName -ErrorAction "Stop"}
								Catch
									{
									
									}
								If ($CurrentApplicationProcess -ne $null)
									{
									
										Write-Host "`tStopping $($_.BaseName)..."
							 			Stop-Process -Name $_.BaseName -Force
									}
								Else
									{
										Write-Host "`t$($_.BaseName) is not running"
									}
							}
					}
#				Write-Host
				Write-Host "Uninistalling $($Application.Name)..." 
			 	$Application.Uninstall()
			}
		Else
			{
				Write-Host "No applications that match the string $($PackageName) are present on this system."
			}
		
		$CommonProgramFiles = $Env:CommonProgramFiles
		$KasperskyCleaner = $CommonProgramFiles + "\Kaspersky_Cleaner\cleaner.exe"
		Write-Host "...running the Kaspersky cleaner $($KasperskyCleaner)"
		
		Start-Process -FilePath "$($KasperskyCleaner)" -ArgumentList "/uc {B9518725-0B76-4793-A409-C6794442FB50}"
		Start-Process -FilePath  "$($KasperskyCleaner)" -ArgumentList "/pc {ED1C2D7E-5C7A-48D8-A697-57D1C080ABA7}"

		If ($Application -ne $null)
			{
				 If ($OSArchitecture -like "*64*")
					{
						$uninstall32 = gci "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($Application.IdentifyingNumber)"} | foreach { gp $_.PSPath } | select UninstallString,PSChildName
						$uninstall64 = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($Application.IdentifyingNumber)"} | foreach { gp $_.PSPath } | select UninstallString,PSChildName
					}
				Else
					{
						$uninstall32 = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ? {$_.PSPath -like "*$($Application.IdentifyingNumber)"} | foreach { gp $_.PSPath } | select UninstallString,PSChildName
					}
			}
			
			if ($uninstall32)
				{
					$uninstall32[0] | % `
						{
							$ThisPackageName = $nul
							$ThisPackageName = $_.PSChildName
							Write-Host "`t$($_.UninstallString)"
							
							$uninstaller32 = $_.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
							$uninstaller32 = $uninstaller32.Trim()
							$a = "we1c0me!"
							[array]$Chararray = ([int[]][char[]]$a)
							$PWDString = ""
							$Chararray | % `
								{
									$PWDString += '{0:X2}' -f $_
								}
							$PWDString
							$KLUninstallPWD = "77653163306d6521"
							start-process "msiexec.exe" -arg "/X $uninstaller32 /qn KLUNINSTPASSWD=$($PWDString) /norestart" -Wait
							
						}
					
				}

	}

	
$PackageNames | % `
	{
		$StartMenuItems = GCI ($ENV:ProgramData + "\Microsoft\Windows\Start Menu\Programs") | ? {$_.Name -like "$($PackageName)*"}
		If ($StartMenuItems -ne $null)
			{
				$StartMenuItems | % `
					{
						Remove-Item $_.FullName -Force -Recurse
					}
			}
	}
$Filename = "Leapfrog.exe"
If (Test-Path ($ENV:PUBLIC + "\Desktop\"+$Filename))
	{
	  Remove-Item -LiteralPath ($ENV:PUBLIC + "\Desktop\" + $Filename) #-WhatIf
	}
$ParentKey = "Leapfrog"
$SubKey = "Tech Support Mailer"
If (Test-Path ( "HKCU:\Software\$($ParentKey)"))
	{	
		$LeapfrogChildRegKeys = @()
		try{[array]$LeapfrogChildRegKeys = GCI -Path "
		HKCU:\Software\$($ParentKey)"}
		catch
			{
		   	
			}
		If ($LeapfrogChildRegKeys.Count -gt 0 -or $LeapfrogChildRegKeys.Count -ne $null )
			{
				If (Test-Path "HKCU:\Software\$($ParentKey)\$($SubKey)")
					{
						Remove-Item "HKCU:\Software\$($ParentKey)\$($SubKey)" #-WhatIf
						$LeapfrogChildRegKeys = @()
						try{[array]$LeapfrogChildRegKeys = GCI -Path "HKCU:\Software\$($ParentKey)"}
						catch
							{
							
							}
						If ($LeapfrogChildRegKeys.Count -eq 0 -or $LeapfrogChildRegKeys.Count -eq $null)
							{
								Remove-Item "HKCU:\Software\$($ParentKey)" #-WhatIf
							}
					}
			
			}
		Else
			{
				Remove-Item "HKCU:\Software\$($ParentKey)" #-WhatIf
			}
	}
