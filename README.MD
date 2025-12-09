# Insert Dune Reference

## Purpose
These scripts scan a system to identify evidence of compromise by Shai-Hulud/Sha1-Hulud.  Remediation of compromise is
currently out of scope, but may be added later.

## Usage

0. This script isn't signed, so you'll probably have to run this command to accept the dangers of running a script from the interwebz:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted
```

1. Clone this repository
2. Fire up a PowerShell window, cd on over to where you cloned the repo
3. Run the script `.\find-sandworm.ps1`
4. Review the `.log` file output for messages indicating something malicious/compromised was found

## Methods
The script currently looks for the following indicators:

1. Hash of .js files matching an SHA256 hash for a known malicious JS bundle.
2. GitHub yml file names known to be malicious.
3. Git branch names on a repository's origin known to be malicious.
4. List of NPM packages & versions known to be compromised, looked for in files called `package.json` and `package-lock.json`.

### Future Methods
1. Search `.js` files for code that targets git or npm APIs to do naughty things
2. Search for code that executes TruffleHog (which is how it steals credentials)
3. Call our own TruffleHog to find any credentials that need to be rotated

## TODO
* Improve readability of log output
* Add support for multiple file formats containing known-bad packages
* Does someone have hashes of known bad files?
* Error handling
* Fall back to `find-sandworm-slow.ps1`
  * This threat is very unlikely to have indicators of compromise outside of a git repository, so global scanning is probably not useful at this time.
* Finish `find-sandworm-slow.ps1`
* Automatic removal of malicious files?
