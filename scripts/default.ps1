properties {
    $configuration = $configuration
}

Include ".\core\utils.ps1"

$projectFileName = "project.json"
$solutionRoot = (get-item $PSScriptRoot).parent.fullname
$artifactsRoot = "$solutionRoot\artifacts"
$artifactsBuildRoot = "$artifactsRoot\build"
$artifactsTestRoot = "$artifactsRoot\test"
$artifactsPackagesRoot = "$artifactsRoot\packages"
$srcRoot = "$solutionRoot\src"
$testsRoot = "$solutionRoot\test"
$globalFilePath = "$solutionRoot\global.json"
$appProjects = Get-ChildItem "$srcRoot\**\$projectFileName" | foreach { $_.FullName }
$testProjects = Get-ChildItem "$testsRoot\**\$projectFileName" | foreach { $_.FullName }
$packableProjectDirectories = @("$srcRoot\IdentityServer4.AccessTokenValidation")

task default -depends TestParams, Setup, Build, RunTests, Pack

task TestParams { 
	Assert ($configuration -ne $null) '$configuration should not be null'
}

task Setup {
    if((test-path $globalFilePath) -eq $false) {
        throw "global.json doesn't exists. globalFilePath: $globalFilePath"
    }
	
	$globalSettingsObj = (get-content $globalFilePath) -join "`n" | ConvertFrom-Json
	$hasSdk = $globalSettingsObj | Get-Member | 
		where { $_.MemberType -eq "NoteProperty" } | 
		Test-Any { $_.Name -eq "sdk" }
		
	if($hasSdk) {
		$hasVersion = $globalSettingsObj.sdk | Get-Member | 
			where { $_.MemberType -eq "NoteProperty" } | 
			Test-Any { $_.Name -eq "version" }
			
		if($hasVersion) {
			$runtimeVersion = $globalSettingsObj.sdk.version;
			Write-Output "Setting runtime v$runtimeVersion as active runtime"
			dnvm use $globalSettingsObj.sdk.version
		}
		else {
			throw "global.json doesn't contain sdk version."
		}
	}
	else {
		throw "global.json doesn't contain sdk information."
	}
}

task Build -depends Restore, Clean {
	
	$appProjects | foreach {
		dnu build "$_" --configuration $configuration --out "$artifactsBuildRoot"
    }
    
    $testProjects | foreach {
		dnu build "$_" --configuration $configuration --out "$artifactsBuildRoot"
    }
}

task RunTests -depends Restore, Clean {
	$testProjects | foreach {
		Write-Output "Running tests for '$_'"
		dnx --project "$_" Microsoft.Dnx.ApplicationHost test
	}
}

task Pack -depends Restore, Clean {
	$packableProjectDirectories | foreach {
		dnu pack "$_" --configuration $configuration --out "$artifactsPackagesRoot" --quiet
	}
}

task Restore {
	@($srcRoot, $testsRoot) | foreach {
        dnu restore "$_"
    }
}

task Clean {
    $directories = $(Get-ChildItem "$solutionRoot\artifacts*"),`
        $(Get-ChildItem "$solutionRoot\**\**\bin")
		
    $directories | foreach ($_) { Remove-Item $_.FullName -Force -Recurse }
}