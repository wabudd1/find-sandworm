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
        $npmPackages = [System.Collections.Generic.List[NpmPackage]]::new()
    
        #####
        # File names to search for.
        #####
        $npmFileNames = @("package.json", "package-lock.json")
    
        ######
        # All output goes to host and this file.
        ######
        $startDate = Get-Date -Format FileDateTime
        $logFileName = ""
        
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
                    if (!($line.StartsWith("#")) -and $line.Length -gt 0) {
                        $packageObj = [NpmPackage]::new(@{
                            pkgColonVer = $line
                        })
                        
                        $npmPackages.Add($packageObj)
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
            #$message | Out-Host
        }

        #######################
        # Main                #
        #######################
        Clear-Host
        $PSStyle.Progress.View = 'Classic'
        $compyInfo = Get-ComputerInfo
        $logFileName = ".\" + $compyInfo.CsName + "_" + $startDate + ".log"
        Log("Sandworm finder.... go!")

        AppendToLog($compyInfo)

        $npmPackages = parsePackageList($packagesPath)

        $diskDrives = Get-PSDrive -PSProvider 'FileSystem' | where-object { $_.Name -ne "Temp" }
    
        Log("Found " + $diskDrives.Count + " drive(s) on the system.")
    
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
            Log("Git is not installed or is not in the current users PATH.")
        }
    
        #####
        # Loop through all disk drives on the system.
        #####
        $diskIterator = 1
        foreach ($disk in $diskDrives)
        {
            Log("Scanning " + $disk.Root + " out of " + $diskDrives.Count + " disks.")
            $diskProgressParams = @{
                Id = 0
                Activity = "Scanning system"
                Status = "Drive " + ($diskIterator) + " out of " + $diskDrives.Count
                PercentComplete = ($diskIterator / $diskDrives.Count) * 100
                CurrentOperation = "Scanning drive " + $disk.Root
            }
            Write-Progress @diskProgressParams

            if ($gitExists -eq $true)
            {    
                #####
                # Look for directories called ".git" to identify repositories.
                #####
                $repositories = Get-ChildItem -Path $disk.Root -Directory ".git" -Recurse -Force -ErrorAction SilentlyContinue
    
                if ($repositories.Count -gt 0)
                {
                    Log("Found " + $repositories.Count + " git repositories.")

                    $repoIterator = 1
                    foreach ($repoDir in $repositories)
                    {
                        $repoProgressParams = @{
                            Id = 1
                            ParentId = 0
                            Activity = "Scanning repositories"
                            Status = "Repository " + ($repoIterator) + " out of " + $repositories.Count
                            PercentComplete = ($repoIterator / $repositories.Count) * 100
                            CurrentOperation = $repoDir.Parent.ToString()
                        }

                        Log("Scanning repository at " + $repoDir.Parent.ToString())
                        Write-Progress @repoProgressParams

                        #####
                        # Check for branches with malicious name.
                        #####
                        $badBranches = git -C $repoDir.Parent.ToString() ls-remote --heads origin | Select-String -pattern $maliciousBranchName
                        if ($badBranches.Count -gt 0)
                        {
                            Log("Found " + $badBranches.Count + " suspicious branch(es):")
                            AppendToLog($badBranches)
                        }
    
                        #####
                        # Look for dirty packages referenced by NPM JSON files
                        #####
                        $npmFilesFound = Get-Childitem -Path $repoDir.Parent.ToString() -Include $npmFileNames -Recurse -force -ErrorAction SilentlyContinue
                        $dirtyFileCount = 0;
                        if ($npmFilesFound.Count -gt 0)
                        {
                            Log("Found " + $npmFilesFound.Count + " NPM files to scan.")
    
                            $npmFileIterator = 1
                            foreach ($npmFileFound in $npmFilesFound) {
                                $npmProgressParams = @{
                                    Id = 2
                                    ParentId = 1
                                    Activity = "Scanning npm package files"
                                    Status = "File " + ($npmFileIterator) + " out of " + $npmFilesFound.Count
                                    PercentComplete = ($npmFileIterator / $npmFilesFound.Count) * 100
                                    CurrentOperation = $npmFileFound.ToString()
                                }

                                Write-Progress @npmProgressParams

                                # Annoying intentionally malformed package.json
                                if ($null -ne ($npmFileFound.ToString() | Select-String "malformed_package_json")) {
                                    continue
                                }

                                $dirtyFile = $false
                                try {
                                    $jsonFile = Get-Content -Raw -Path $npmFileFound.ToString() | ConvertFrom-Json -AsHashtable
                                }
                                catch {
                                    Log("Failed to parse file:  " + $npmFileFound.ToString())
                                }
                                
                                if ($null -ne $jsonFile) {
                                    if ($npmfileFound.Name -eq "package.json") {
                                        $foundPackages = [System.Collections.Generic.List[NpmPackage]]::new()

                                        $pkgIterator = 1
                                        foreach ($pkg in $npmPackages) {
                                            $pkgProgressParams = @{
                                                Id = 3
                                                ParentId = 2
                                                Activity = "Scanning package.json references"
                                                Status = "Package ref " + ($pkgIterator) + " out of " + $npmPackages.Count
                                                PercentComplete = ($pkgIterator / $npmPackages.Count) * 100
                                                CurrentOperation = $pkg.ToString()
                                            }
                                            
                                            Write-Progress @pkgProgressParams
                                            $packageVersion = $jsonFile.dependencies.$pkg

                                            if ($null -ne $packageVersion) {
                                                $foundPackages += $pkg
                                            }

                                            $devPackageVer = $jsonFile.devDependencies.$pkg

                                            if ($null -ne $devPackageVer) {
                                                $foundPackages += $pkg
                                            }

                                            $pkgIterator++
                                            if ($pkgIterator -gt $npmPackages.Count) {
                                                $pkgProgressParams.Completed = $true
                                            }
                                            Write-Progress @pkgProgressParams
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
                                            $dirtyFile = $true
                                            Log("File " + $npmFileFound.ToString() + " contains " + $matchingLines.Count + "possibly infected package(s).")
                                        }
                                    }
                                }

                                if ($dirtyFile -eq $true) {
                                    $dirtyFileCount++
                                }

                                $npmFileIterator++
                                
                                if ($npmFileIterator -gt $npmFilesFound.Count) {
                                    $npmProgressParams.Completed = $true
                                }
                                
                                Write-Progress @npmProgressParams
                            }

                            Log($dirtyFileCount.ToString() + " package files with references to infected package(s) out of " + $npmFilesFound.Count + " scanned.")
                        } else {
                            Log("No NPM files found in this repository.")
                        }
    
                        #####
                        # Look for malicious JS file(s).
                        #####
                        $javaScriptFilesFound = Get-ChildItem -Path $repoDir -Filter "*.js" -Recurse -Force -ErrorAction SilentlyContinue
                        $maliciousJsFileCount = 0
                        if ($javaScriptFilesFound.Count -gt 0)
                        {
                            Log("Found " + $javaScriptFilesFound.Count + " JS files in " + $repoDir)
                            $jsFileIterator = 1
                            foreach ($jsFile in $javaScriptFilesFound)
                            {
                                $jsFileProgressParams = @{
                                    Id = 4
                                    ParentId = 2
                                    Activity = "Scanning JavaScript files"
                                    Status = "File " + ($jsFileIterator) + " out of " + $javaScriptFilesFound.Count
                                    PercentComplete = ($jsFileIterator / $javaScriptFilesFound.Count) * 100
                                    CurrentOperation = $jsFile.Name
                                }
                                Write-Progress @jsFileProgressParams

                                $hash = Get-FileHash $jsFile -Algorithm SHA256
                                if ($hash.Hash -eq $maliciousHash)
                                {
                                    Log("SHA256 Hash of file at " + $jsFile.ToString() + " matches a known malicious file.")
                                    $maliciousJsFileCount++
                                }

                                $jsFileIterator++
                                if ($jsFileIterator -gt $javaScriptFilesFound.Count) {
                                    jsFileProgressParams.Completed = $true
                                }
                                Write-Progress @jsFileProgressParams
                            }

                            Log($maliciousJsFileCount + "malicious JavaScript files out of " + $javaScriptFilesFound.Count + " scanned.")
                        } else {
                            Log("No JavaScript files found in this repository.")
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
                            Log("No workflow files found in this repository.")
                        }

                        $repoIterator++

                        if ($repoIterator -gt $repositories.Count) {
                            $repoProgressParams.Completed = $true
                        }

                        Write-Progress @repoProgressParams
                    }
                }
                else {
                    Log("Did not find any git repositories on drive " + $disk.Name)
                }
            }
            else {
                Log("Git does not exist on this system. Exiting.")
            }

            $diskIterator++
            if ($diskIterator -gt $diskDrives.Count) {
                $diskProgressParams.Completed = $true
            }
            Write-Progress @diskProgressParams
        }
        
        Log("All done.")
        Write-Host "Done.  Results can be found in " + $logFileName
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

    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $properties.$Property
        }
    }

    # Constructor for package definitions formatted "package:version"
    NpmPackage([string] $pkgColonVer)
    {
        $splitted = $pkgColonVer -Split ":"
        $this.Init(@{ PackageName = $splitted[0]; PackageVersion = $splitted[1]; })
    }
}

# Execute Order 66
Find-Sandworm
