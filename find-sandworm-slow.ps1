#######################
# Variables           #
#######################

# SHA256 Hash of bundle.js known to be malicious
# See:  https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised#indicators-of-compromise
$maliciousHash = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09";

## Malicious GitHub Actions workflow name
$maliciousWorkflow = "shai-hulud-workflow.yml";

## List of packages, one per line.
# TODO:  Get a list that is trustworthy/up to date.
$npmPackages = Get-Content -Path ".\stringsToFind.txt";

## File names to search for.
$npmFileNames = @("package.json", "package-lock.json");

## Variable to store list of files matching the above names.
$filesFound = @();

#######################
# Main                #
#######################

$compInfo = Get-ComputerInfo;
$logFileName = ".\" + $compInfo.CsName + ".txt";
$compInfo | Out-File $logFileName;

## TODO:  OneDrive?
$diskDrives = Get-PSDrive -PSProvider 'FileSystem' | where-object { $_.Name -ne "Temp" };

Log("Found " + $diskDrives.Count + " drives on the system.");

foreach ($disk in $diskDrives)
{
    ###### Look for dirty packages referenced by NPM JSON files
    $npmFilesFound += Get-Childitem -Path $disk.Name -Include $npmFileNames -Recurse -force -ErrorAction SilentlyContinue;

    if ($npmFilesFound.Count -gt 0)
    {
        Log("Found " + $npmFilesFound.Count + " files to scan in " + $disk.Name);

        foreach ($npmFileFound in $npmFilesFound)
        {
            $dirtyFile = $false;
            $fileContent = Get-Content($npmFileFound);
            
            foreach ($packageName in $npmPackages)
            {
                $matchingLines = Select-String -Path $fileContent -Pattern $packageName -AllMatches;
                if ($matchingLines.Count -gt 0)
                {
                    $dirtyFile = $true;
                    Log("File " + $npmFileFound.ToString() + " contains " + $matchingLines.Count + "possibly infected package(s).");
                    AppendToLog($matchingLines);
                }
            }

            if ($dirtyFile -eq $false)
            {
                Log("No suspicious packages in file " + $npmFileFound.ToString());
            }
        }
    }

    ##### Look for malicious JS file(s).
    $javaScriptFilesFound = Get-ChildItem -Path $disk.Name -Include "*.js" -Recurse -Force -ErrorAction SilentlyContinue;
    if ($javaScriptFilesFound.Count -gt 0)
    {
        Log("Found " + $javaScriptFilesFound.Count + " JS files in " + $disk.Name);

        foreach ($jsFile in $javaScriptFilesFound)
        {
            $hash = Get-FileHash $jsFile -Algorithm SHA256;
            if ($hash.Hash -eq $maliciousHash)
            {
                Log("SHA256 Hash of file at " + $jsFile.ToString() + " matches a known malicious file.");
            }
        }
    }
    else {
        Out-Host "No JS files found in this repository.";
    }

    #### Look for malicious GitHub Actions Workflows
    $workflowFilesFound = Get-ChildItem -Path $disk.Name -Filter $maliciousWorkflow -Recurse -Force -ErrorAction SilentlyContinue;
    if ($workflowFilesFound.Count -gt 0)
    {
        foreach ($workflowFile in $workflowFilesFound)
        {
            Log("Workflow file " + $workflowFile.ToString() + " is probably malicious.");
        }
    }
    else {
        Log("No malicious workflow files found in this repository.");
    }
}

function Log {
    param (
        $message
    )
    $timeStamp = Get-Date -Format FileDateTime;
    $message = $timeStamp + " | " + $message;
    $message | Out-File -FilePath $logFileName -Append -NoClobber;
    $message | Out-Host;
}

function AppendToLog {
    param (
        $message
    )
    $message | Out-File -FilePath $logFileName -Append -NoClobber;
}
