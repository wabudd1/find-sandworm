#######################
# Variables           #
#######################

######
# Amount of things scanned
######
$driveCount = 0
$repositoryCount = 0

######
# Detection counts by severity
######
$lowCount = 0
$mediumCount = 0
$highCount = 0

#####
# SHA256 Hashes of .js files known to be malicious.
#####
$hashListPath = ".\maliciousHashes.txt"
$maliciousHashes = $null

$fileListPath = ".\maliciousFiles.txt"
$maliciousFiles = $null

#####
# Name of git branch that could be malicious.
#####
$maliciousBranchName = $null

######
# List of packages, one per line.
######
$packageListPath = ".\compromised-packages.txt"
$maliciousPackages = $null

#####
# Names of files to search for package definitions.
#####
$npmFileNames = $null

######
# All output goes to host and this file.
######
$startDate = Get-Date -Format FileDateTime
$logFileName = ""

function parseNaughtyList {
    param (
        $filePath,
        $isPackageFile
    )
    
    $commentCharacter = "#"
    $fileExtension = $filePath.Split(".")
    $fileContent = Get-Content -Path $filePath
    $returnTupleList = [System.Collections.Generic.List[System.Tuple[string, string]]]::new()
    if ($fileExtension -eq "txt") {
        
        $splitCharacter = $null
        if ($isPackageFile -eq $true) {
            $splitCharacter = ":"
        }
        else {
            $splitCharacter = ","
        }

        foreach ($line in $fileContent) {
            if (!($line.StartsWith($commentCharacter)) -and $line.Length -gt 0) {
                $splitLine = $line.Split($splitCharacter)
                $newTuple = [Tuple]::Create($splitLine[0], $splitLine[1])
                $returnTupleList.Add($newTuple)
            }
        }
    }
    else {
        Out-Host "Can only parse package lists in .txt format right now."
    }

    return $returnTupleList
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
function Find-Sandworm
{
    [CmdletBinding()]
    param()
    begin {
        Clear-Host

        # Classic enables a shiny progress bar
        $PSStyle.Progress.View = 'Classic'

        # Log file with computer name
        $compyInfo = Get-ComputerInfo
        $logFileName = ".\" + $compyInfo.CsName + "_" + $startDate + ".log"

        # Details about this computer that may be helpful.
        AppendToLog($compyInfo)

        #####
        # Test if git is installed, so we can later check for naughty branches.
        #####
        $gitExists
    
        try
        {
            git -v | Out-Null
            $gitExists = $true
        }
        catch [System.Management.Automation.CommandNotFoundException]
        {
            $gitExists = $false
            
            # Note:  If the user running this script does not have `git` in their path, then their git install is bad
            #        and should feel bad.  The author of this script is not about to hunt down their git executable.
            Log("Git is not installed or is not in the current users PATH.")
            throw "Git is not installed or is not in the current users PATH.  No point in continuing."
        }

        ### TODO:  Maybe move these two to a text file for easier configuration.
        $maliciousBranchName = "shai-hulud"
        $npmFileNames = @("package.json", "package-lock.json")

        ##################
        # If any files didn't parse or if git is missing, the script cannot continue.
        ##################
        $maliciousHashes = parseNaughtyList($hashListPath)
        if ($maliciousHashes.Count -lt 1) {
            throw "No hashes were parsed."
        }

        $maliciousFiles = parseNaughtyList($fileListPath)
        if ($maliciousFiles.Count -lt 1) {
            throw "No file names were parsed."
        }

        $maliciousPackages = parseNaughtyList($packageListPath)
        if ($maliciousPackages.Count -lt 1) {
            throw "No file names were parsed."
        }
    }
    process {
        Log("Begin scan for Shai-Hulud indicators of compromise.")

        # Scan all local file systems in case the user has a secondary partition or something.
        $diskDrives = Get-PSDrive -PSProvider 'FileSystem' | where-object { $_.Name -ne "Temp" }
        $driveCount = $diskDrives

        #####
        # Loop through all disk drives on the system.
        #####
        $diskIterator = 1
        foreach ($disk in $diskDrives)
        {
            $diskProgressParams = @{
                Id = 0
                Activity = "Scanning system"
                Status = "Drive " + ($diskIterator) + " out of " + $diskDrives.Count
                PercentComplete = ($diskIterator / $diskDrives.Count) * 100
                CurrentOperation = "Scanning drive " + $disk.Root
            }
            Write-Progress @diskProgressParams

            #####
            # Look for directories called ".git" to identify repositories.
            #####
            $repositories = Get-ChildItem -Path $disk.Root -Directory ".git" -Recurse -Force -ErrorAction SilentlyContinue

            if ($repositories.Count -gt 0)
            {
                $repositoryCount += $repositories.Count

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

                    Write-Progress @repoProgressParams

                    #####
                    # Check for branches with malicious name.
                    #####
                    $badBranches = git -C $repoDir.Parent.ToString() ls-remote --heads origin | Select-String -pattern $maliciousBranchName
                    if ($badBranches.Count -gt 0)
                    {
                        Log("Found " + $badBranches.Count + " suspicious branch(es):")
                        $highCount += $badBranches.Count
                        AppendToLog($badBranches)
                    }

                    #####
                    # Look for dirty packages referenced by NPM JSON files
                    #####
                    $npmFilesFound = Get-Childitem -Path $repoDir.Parent.ToString() -Include $npmFileNames -Recurse -force -ErrorAction SilentlyContinue

                    if ($npmFilesFound.Count -gt 0)
                    {
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

                            # Skip annoying intentionally malformed package.json
                            if ($null -ne ($npmFileFound.ToString() | Select-String "malformed_package_json")) {
                                continue
                            }

                            try {
                                $jsonFile = Get-Content -Raw -Path $npmFileFound.ToString() | ConvertFrom-Json -AsHashtable
                            }
                            catch {
                                Log("Failed to parse file:  " + $npmFileFound.ToString() + ". Consider reviewing this file manually.")
                            }
                            
                            if ($null -ne $jsonFile) {
                                if ($npmfileFound.Name -eq "package.json") {
                                    $foundPackages = [System.Collections.Generic.List[Tuple[string, string]]]::new()

                                    $pkgIterator = 1
                                    foreach ($pkg in $maliciousPackages) {
                                        $pkgProgressParams = @{
                                            Id = 3
                                            ParentId = 2
                                            Activity = "Scanning package.json references"
                                            Status = "Package ref " + ($pkgIterator) + " out of " + $maliciousPackages.Count
                                            PercentComplete = ($pkgIterator / $maliciousPackages.Count) * 100
                                            CurrentOperation = $pkg.Item0.ToString()
                                        }
                                        
                                        Write-Progress @pkgProgressParams

                                        # Retrieves the value of the "dependencies" collection with the key defined in $pkg.Item1
                                        # Example:
                                        #
                                        # "dependencies": {
                                        #   "@angular/animations": "19.2.17"
                                        # }
                                        # if $pkg.Item1 were "@angular/animations", the value retrieved would be "19.2.17"

                                        $packageVersion = $jsonFile.dependencies.$pkg.Item1

                                        if ($null -ne $packageVersion -and $pkg.Item2 -eq $packageVersion) {
                                            $foundPackages += $pkg
                                        }

                                        # Do it again for "devDependencies" collection
                                        $devPackageVer = $jsonFile.devDependencies.$pkg.Item1

                                        if ($null -ne $devPackageVer -and $pkg.Item2 -eq $packageVersion) {
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
                                        # Medium severity because it's not 100% certain something bad happened.
                                        $mediumCount += $foundPackages.Count

                                        Log("File " + $npmFileFound.ToString() + " references " + $foundPackages.Count + "possibly malicious package(s):")
                                        AppendToLog($foundPackages)
                                    }
                                }
                                elseif ($npmFileFound -eq "package-lock.json") {
                                    $jsonFileText = Get-Content $npmFileFound

                                    $matchingLines = $jsonFileText | Select-String -Pattern $pkg.Item1 -AllMatches

                                    if ($matchingLines.Count -gt 0) {
                                        $mediumCount += $matchingLines.Count
                                        Log("File " + $npmFileFound.ToString() + " references " + $matchingLines.Count + "possibly malicious package(s):")
                                    }
                                }
                            }

                            $npmFileIterator++
                            
                            if ($npmFileIterator -gt $npmFilesFound.Count) {
                                $npmProgressParams.Completed = $true
                            }
                            
                            Write-Progress @npmProgressParams
                        }
                    }

                    #####
                    # Look for malicious JS file(s).
                    #####
                    $javaScriptFilesFound = Get-ChildItem -Path $repoDir -Filter "*.js" -Recurse -Force -ErrorAction SilentlyContinue
                    if ($javaScriptFilesFound.Count -gt 0)
                    {
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
                            foreach ($badHash in $maliciousHashes) {
                                if ($hash.Hash -eq $badHash) {
                                    $highCount++
                                    Log("SHA256 Hash of file at " + $jsFile.ToString() + " matches that of a known malicious file.")
                                }
                            }

                            $jsFileIterator++
                            if ($jsFileIterator -gt $javaScriptFilesFound.Count) {
                                jsFileProgressParams.Completed = $true
                            }
                            Write-Progress @jsFileProgressParams
                        }
                    }

                    #####
                    # Look for malicious files by name.
                    #####
                    foreach ($badFileName in $maliciousFiles) {
                        $filesFound = Get-ChildItem -Path $repoDir -Filter $maliciousWorkflow -Recurse -Force -ErrorAction SilentlyContinue
                        if ($filesFound.Count -gt 0) {
                            foreach ($foundFile in $filesFound) {
                                $mediumCount++
                                Log("File " + $foundFile.ToString() + " matches the name of a possibly malicious file.")
                            }
                        }
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

            $diskIterator++
            if ($diskIterator -gt $diskDrives.Count) {
                $diskProgressParams.Completed = $true
            }
            Write-Progress @diskProgressParams
        }
    }
    end {

        Log("Finished scanning")
        AppendToLog("Disk drives:  " + $driveCount)
        AppendToLog("Repositories:  " + $repositoryCount)
        AppendToLog("Low risk findings:   " + $lowCount)
        AppendToLog("Medium risk findings:  " + $mediumCount)
        AppendToLog("High risk findings:  " + $highCount)
        Write-Host "Done.  Results can be found in " + $logFileName
        Read-Host "Press any key to exit."
    }
    clean {
        # TODO:  Free up variables.
    }
}

# Execute Order 66
Find-Sandworm
