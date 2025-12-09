function Find-Sandworm
{
    <#
    .SYNOPSIS
    Scans local computer for signs of Sha1-Hulud compromise.
    
    .DESCRIPTION
    Uses various methods to identify whether anything on the local computer or any git repositories has been compromised
    by Shai-Hulud/Sha1-Hulud.  Outputs positive or negative results to <computer name>.txt in the working directory as
    well as the console host.
    
    .EXAMPLE
    .\sandworm-finder.ps1
    
    .NOTES
    This version of the script ignores files that are not part of a git repository.

    Methods used for identification:
        1. Hash of .js files matching an SHA256 hash for a known malicious JS bundle.
        2. GitHub yml file names known to be malicious.
        3. Git branch names on a repository's origin known to be malicious.
        4. List of NPM packages & versions known to be compromised, looked for in files called `package.json` and
            `package-lock.json`.
        TODO:  Look for code in JS files that do naughty things.
        TODO:  TruffleHog usage by compromised packages.
        TODO:  Add TruffleHog to scan local system for secrets that need to be rotated.
    #>
    [CmdletBinding()]
    param()
    process {
        #######################
        # Variables           #
        #######################

        #####
        # SHA256 Hash of bundle.js known to be malicious
        # See:  https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised#indicators-of-compromise
        #####
        $maliciousHash = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    
        #####
        # Malicious GitHub Actions workflow name
        #####
        $maliciousWorkflow = "shai-hulud-workflow.yml"
    
        #####
        # Name of git branch that could be malicious.
        #####
        $maliciousBranchName = "shai-hulud"
    
        ######
        # List of packages, one per line.
        ######
        $packagesPath = ".\compromised-packages.txt"
        $npmPackages = @{ }
    
        #####
        # File names to search for.
        #####
        $npmFileNames = @("package.json", "package-lock.json")
    
        ######
        # All output goes to host and this file.
        ######
        $logFileName = ".\" + $compInfo.CsName + ".txt"
        
        #######################
        # Helper Functions    #
        #######################
        <#
        .SYNOPSIS
        Parses package list file into an [NpmPackage] object.
        
        .DESCRIPTION
        Parses a list of NPM packages in a text file into an [NpmPackage] object for ease of use.
        
        .PARAMETER filePath
        Path relative to working directory containing a text file with each line containing a package:version.
        
        .EXAMPLE
        parsePackageList(".\packageList.txt")
        
        .NOTES
        Support for other formats (like CSV) coming later because I found a text file that looks comprehensive.
        #>
        function parsePackageList {
            param (
                $filePath
            )
            $fileExtension = $filePath.Split(".")
            $fileContent = Get-Content -Path $filePath

            if ($fileExtension -eq "txt") {
                foreach ($line in $fileContent) {
                    if (!($line.StartsWith("#"))) {
                        $npmPackages.Add([NpmPackage]::new(@{
                            $pkgColonVer = $line
                        }))
                    }
                }
            }
            else {
                Out-Host "Can only parse package lists in .txt format right now."
            }
        }

        <#
        .SYNOPSIS
        Appends a longer (possibly multi-line) string to the log.
        
        .DESCRIPTION
        Appends the given string to the log output without timestamp.  Adds newlines before and after for readability.
        
        .PARAMETER message
        String to append.
        
        .EXAMPLE
        AppendToLog(Object.ToString())
        
        .NOTES
        Meant to output lengthy cmdlet or object strings while keeping things nicely formatted.  Before calling this,
        probably best to call Log() with some kind of text to describe what comes after.
        #>
        function AppendToLog {
            param (
                $message
            )
            "`r`n" + $message + "`r`n" | Out-File -FilePath $logFileName -Append -NoClobber
        }

        <#
        .SYNOPSIS
        Log a timestamped message to file and host.

        .DESCRIPTION
        Appends a timestamp to the front of a given message and outputs it to a text file and the console host.

        .PARAMETER message
        Message to log.

        .EXAMPLE
        Log("An log message")

        .NOTES
        Best to use this for logging one-liner messages.  Use AppendToLog() for logging cmdlet or other lengthy outputs.
        #>
        function Log {
            param (
                $message
            )
            $timeStamp = Get-Date -Format FileDateTime
            $message = $timeStamp + " | " + $message
            $message | Out-File -FilePath $logFileName -Append -NoClobber
            $message | Out-Host
        }

        #######################
        # Main                #
        #######################
        Log("Sandworm finder.... go!")

        AppendToLog(Get-ComputerInfo)

        $npmPackages = parsePackageList($packagesPath)

        $diskDrives = Get-PSDrive -PSProvider 'FileSystem' | where-object { $_.Name -ne "Temp" }
    
        Log("Found " + $diskDrives.Count + " drives on the system.")
    
        #####
        # Test if git is installed, so we can later check for naughty branches.
        #####
        $gitExists = $false
    
        try
        {
            git -v | Out-Null
            $gitExists = $true
        }
        catch [System.Management.Automation.CommandNotFoundException]
        {
            # Note:  If the user running this script does not have `git` in their path, then their git install is bad
            #        and should feel bad.  The author of this script is not about to hunt down their git executable.
            Out-Host "Git is not installed or is not in the current users PATH."
        }
    
        #####
        # Loop through all disk drives on the system.
        #####
        foreach ($disk in $diskDrives)
        {
            if ($gitExists -eq $true)
            {
                Log("Searching " + $disk.Name + " for git repositories.")
    
                #####
                # Look for directories called ".git" to identify repositories.
                #####
                $repositories = Get-ChildItem -Path $disk -Directory ".git" -Recurse -Force -ErrorAction SilentlyContinue
    
                if ($repositories.Count -gt 0)
                {
                    Log("Found " + $repositories.Count + " git repos.")
                    foreach ($repoDir in $repositories)
                    {
                        #####
                        # Check for branches with malicious name.
                        #####
                        $badBranches = git -C $repoDir.Parent ls-remote --heads origin | Select-String -pattern $maliciousBranchName
                        if ($badBranches.Count -gt 0)
                        {
                            Log("Suspicious branch(es) found:"):
                            AppendToLog($badBranches)
                        }
                        else {
                            Log("Repository at " + $repoDir + " is clear of suspicious branches.")
                        }
    
                        #####
                        # Look for dirty packages referenced by NPM JSON files
                        #####
                        $npmFilesFound = Get-Childitem -Path $repoDir -Include $npmFileNames -Recurse -force -ErrorAction SilentlyContinue
    
                        if ($npmFilesFound.Count -gt 0)
                        {
                            Log("Found " + $npmFilesFound.Count + " files to scan in " + $repoDir)
    
                            foreach ($npmFileFound in $npmFilesFound) {
                                $dirtyFile = $false
                                $jsonFile = Get-Content -Raw $npmFileFound | ConvertFrom-Json
                                
                                if ($npmfileFound.Name -eq "package.json") {
                                    $foundPackages = @{}

                                    foreach ($pkg in $npmPackages) {
                                        $packageVersion = $jsonFile.dependencies.$pkg

                                        if ($null -ne $packageVersion) {
                                            $foundPackages += $pkg
                                        }

                                        $devPackageVer = $jsonFile.devDependencies.$pkg

                                        if ($null -ne $devPackageVer) {
                                            $foundPackages += $pkg
                                        }
                                    }

                                    if ($foundPackages.Count -gt 0)
                                    {
                                        $dirtyFile = $true
                                        Log("File " + $npmFileFound.ToString() + " contains " + $foundPackages.Count + "possibly infected package(s).")
                                        AppendToLog($foundPackages)
                                    }
                                }
                                elseif ($npmFileFound -eq "package-lock.json") {
                                    $jsonFileText = Get-Content $npmFileFound

                                    $matchingLines = $jsonFileText | Select-String -Pattern $pkg.PackageName -AllMatches

                                    if ($matchingLines.Count -gt 0) {
                                        Log("File " + $npmFileFound.ToString() + " contains " + $matchingLines.Count + "possibly infected package(s).")
                                    }
                                }
    
                                if ($dirtyFile -eq $false)
                                {
                                    Log("No suspicious packages in file " + $npmFileFound.ToString())
                                }
                            }
                        }
    
                        #####
                        # Look for malicious JS file(s).
                        #####
                        $javaScriptFilesFound = Get-ChildItem -Path $repoDir -Include "*.js" -Recurse -Force -ErrorAction SilentlyContinue
                        if ($javaScriptFilesFound.Count -gt 0)
                        {
                            Log("Found " + $javaScriptFilesFound.Count + " JS files in " + $repoDir)
    
                            foreach ($jsFile in $javaScriptFilesFound)
                            {
                                $hash = Get-FileHash $jsFile -Algorithm SHA256
                                if ($hash.Hash -eq $maliciousHash)
                                {
                                    Log("SHA256 Hash of file at " + $jsFile.ToString() + " matches a known malicious file.")
                                }
                            }
                        }
                        else {
                            Log("No JS files found in this repository.")
                        }
    
                        #####
                        # Look for malicious GitHub Actions Workflows.
                        #####
                        $workflowFilesFound = Get-ChildItem -Path $repoDir -Filter $maliciousWorkflow -Recurse -Force -ErrorAction SilentlyContinue
                        if ($workflowFilesFound.Count -gt 0)
                        {
                            foreach ($workflowFile in $workflowFilesFound)
                            {
                                Log("Workflow file " + $workflowFile.ToString() + " is probably malicious.")
                            }
                        }
                        else {
                            Log("No malicious workflow files found in this repository.")
                        }
                    }
                }
            }
        }
    }
}

<#
    Class to hold a package definition as separate Package Name and Version variables.  Also helps me stay sane.
#>
class NpmPackage {
    ### Name of the package including scope e.g., @angular/core
    [string] $PackageName

    ### Version number of the package, not including range characters (^ > < ~ etc)
    [string] $PackageVersion

    NpmPackage() { $this.Init(@{}) }

    # Constructor for package definitions formatted "package:version"
    NpmPackage([string] $pkgColonVer)
    {
        $splitted = $pkgColonVer -Split ":"
        $this.Init(@{ PackageName = $splitted[0]; PackageVersion = $splitted[1]; })
    }
}

# Execute Order 66
Find-Sandworm
