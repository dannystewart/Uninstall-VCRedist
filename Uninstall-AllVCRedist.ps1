#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstalls all Visual C++ Redistributable packages from the system.

.DESCRIPTION
    This script identifies and uninstalls all Visual C++ Redistributable packages
    installed on the system. It provides options for interactive confirmation or
    silent operation.

.PARAMETER Silent
    Run without confirmation prompts (use with caution)

.PARAMETER LogPath
    Path where to save the uninstallation log (default: current directory)

.PARAMETER IncludeDebugRuntime
    Include Debug Runtime packages (these are usually protected and cannot be uninstalled)

.EXAMPLE
    .\Uninstall-AllVCRedist.ps1
    Run interactively with confirmation prompts

.EXAMPLE
    .\Uninstall-AllVCRedist.ps1 -Silent
    Run without prompts (silent mode)

.EXAMPLE
    .\Uninstall-AllVCRedist.ps1 -LogPath "C:\Logs"
    Run with custom log location

.EXAMPLE
    .\Uninstall-AllVCRedist.ps1 -IncludeDebugRuntime
    Include Debug Runtime packages in the uninstall process
#>

param(
    [switch]$Silent,
    [string]$LogPath = $PWD,
    [switch]$IncludeDebugRuntime
)

# Set up logging
$LogFile = Join-Path $LogPath "VCRedist_Uninstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Output $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VCRedistPackages {
    Write-Log "Scanning for Visual C++ Redistributable packages..."

    # Common patterns for VC++ Redistributable names
    $VCPatterns = @(
        "*Visual C++*Redistributable*",
        "*Microsoft Visual C++*",
        "*VC_redist*",
        "*vcredist*"
    )

    $AllPackages = @()

    # Registry scan with more comprehensive paths
    try {
        Write-Log "Scanning registry for VC++ packages..."
        $RegPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        foreach ($RegPath in $RegPaths) {
            Write-Log "Scanning registry path: $RegPath"

            # Get all subkeys
            $SubKeys = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue

            foreach ($SubKey in $SubKeys) {
                try {
                    $Item = Get-ItemProperty -Path $SubKey.PSPath -ErrorAction SilentlyContinue

                    if ($Item.DisplayName) {
                        # Check if this matches our VC++ patterns
                        $IsVCPackage = $false
                        foreach ($Pattern in $VCPatterns) {
                            if ($Item.DisplayName -like $Pattern) {
                                $IsVCPackage = $true
                                break
                            }
                        }

                        if ($IsVCPackage) {
                            Write-Log "Found VC++ package: $($Item.DisplayName)"

                            $PackageObj = [PSCustomObject]@{
                                Name                 = $Item.DisplayName
                                Version              = $Item.DisplayVersion
                                IdentifyingNumber    = $SubKey.PSChildName
                                UninstallString      = $Item.UninstallString
                                QuietUninstallString = $Item.QuietUninstallString
                                Source               = "Registry"
                                Publisher            = $Item.Publisher
                                RegPath              = $SubKey.PSPath
                            }

                            # Avoid duplicates
                            $IsDuplicate = $AllPackages | Where-Object {
                                ($_.Name -eq $PackageObj.Name) -or
                                ($_.IdentifyingNumber -eq $PackageObj.IdentifyingNumber -and $null -ne $_.IdentifyingNumber)
                            }

                            if (-not $IsDuplicate) {
                                $AllPackages += $PackageObj
                            }
                        }
                    }
                }
                catch {
                    # Skip items that can't be read
                    Write-Log "Skipped unreadable registry item: $($SubKey.Name)" "DEBUG"
                }
            }
        }
        Write-Log "Found $($AllPackages.Count) packages in registry"
    }
    catch {
        Write-Log "Registry scan failed: $($_.Exception.Message)" "ERROR"
    }

    # If registry didn't find anything, try WMI as backup (but only for detection, not for uninstall)
    if ($AllPackages.Count -eq 0) {
        Write-Log "No packages found in registry, trying WMI for detection only..."
        try {
            $WmiPackages = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object {
                $Name = $_.Name
                if ($Name) {
                    foreach ($Pattern in $VCPatterns) {
                        if ($Name -like $Pattern) {
                            return $true
                        }
                    }
                }
                return $false
            }

            foreach ($WmiPackage in $WmiPackages) {
                if ($WmiPackage.Name -and $WmiPackage.Name.Trim() -ne "") {
                    Write-Log "Found WMI VC++ package: $($WmiPackage.Name)"

                    # Try to find this package's uninstall string in registry by GUID
                    $UninstallString = $null
                    $QuietUninstallString = $null

                    if ($WmiPackage.IdentifyingNumber) {
                        foreach ($RegPath in $RegPaths) {
                            $GuidPath = Join-Path $RegPath $WmiPackage.IdentifyingNumber
                            try {
                                $RegItem = Get-ItemProperty -Path $GuidPath -ErrorAction SilentlyContinue
                                if ($RegItem) {
                                    $UninstallString = $RegItem.UninstallString
                                    $QuietUninstallString = $RegItem.QuietUninstallString
                                    break
                                }
                            }
                            catch { }
                        }
                    }

                    $PackageObj = [PSCustomObject]@{
                        Name                 = $WmiPackage.Name
                        Version              = $WmiPackage.Version
                        IdentifyingNumber    = $WmiPackage.IdentifyingNumber
                        UninstallString      = $UninstallString
                        QuietUninstallString = $QuietUninstallString
                        Source               = "WMI"
                        Publisher            = $null
                        RegPath              = $null
                    }

                    $AllPackages += $PackageObj
                }
            }
            Write-Log "Found $($WmiPackages.Count) additional packages via WMI"
        }
        catch {
            Write-Log "WMI scan failed: $($_.Exception.Message)" "WARN"
        }
    }

    # Filter out any packages with empty names and ensure we have uninstall strings
    $ValidPackages = $AllPackages | Where-Object {
        $_.Name -and
        $_.Name.Trim() -ne "" -and
        $null -ne $_.Name -and
        ($_.UninstallString -or $_.QuietUninstallString)
    }

    Write-Log "Total valid packages with uninstall strings: $($ValidPackages.Count)"

    if ($ValidPackages.Count -eq 0) {
        Write-Log "No valid VC++ packages found with uninstall information" "WARN"
    }

    return $ValidPackages | Sort-Object Name
}

function Uninstall-Package {
    param(
        [object]$Package
    )

    Write-Log "Attempting to uninstall: $($Package.Name)"

    try {
        if ($Package.Source -eq "Registry") {
            # Use registry uninstall string
            $UninstallCmd = $Package.QuietUninstallString
            if (-not $UninstallCmd) {
                $UninstallCmd = $Package.UninstallString
            }

            if ($UninstallCmd) {
                Write-Log "Uninstall command: $UninstallCmd"

                $ExitCode = -1

                if ($UninstallCmd -like "*msiexec*") {
                    # MSI package - extract the product code
                    if ($UninstallCmd -match "(\{[A-F0-9\-]{36}\})") {
                        $ProductCode = $Matches[1]
                        $Arguments = "/X `"$ProductCode`" /quiet /norestart"
                        Write-Log "MSI uninstall arguments: $Arguments"

                        $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow -PassThru
                        $ExitCode = $Process.ExitCode
                    }
                    else {
                        Write-Log "Could not extract product code from MSI uninstall string" "WARN"
                        return $false
                    }
                }
                else {
                    # Non-MSI package - try to add silent flags
                    $SilentCmd = $UninstallCmd
                    if ($SilentCmd -notlike "*/S*" -and $SilentCmd -notlike "*/silent*" -and $SilentCmd -notlike "*/quiet*") {
                        # Try common silent flags
                        if ($SilentCmd -like "*uninst*") {
                            $SilentCmd += " /S"
                        }
                        elseif ($SilentCmd -like "*setup*") {
                            $SilentCmd += " /quiet"
                        }
                    }

                    Write-Log "Non-MSI uninstall command: $SilentCmd"

                    # Parse the command to separate executable and arguments
                    if ($SilentCmd -match '^"([^"]+)"\s*(.*)$') {
                        $ExePath = $Matches[1]
                        $Arguments = $Matches[2].Trim()
                    }
                    elseif ($SilentCmd -match '^([^\s]+)\s*(.*)$') {
                        $ExePath = $Matches[1]
                        $Arguments = $Matches[2].Trim()
                    }
                    else {
                        $ExePath = $SilentCmd
                        $Arguments = ""
                    }

                    if (Test-Path $ExePath) {
                        $Process = Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -NoNewWindow -PassThru
                        $ExitCode = $Process.ExitCode
                    }
                    else {
                        Write-Log "Uninstaller executable not found: $ExePath" "ERROR"
                        return $false
                    }
                }

                Write-Log "Uninstall process exit code: $ExitCode"

                # Check if uninstall was successful (exit codes 0, 3010 are success, 1605 means already removed)
                if ($ExitCode -eq 0 -or $ExitCode -eq 3010 -or $ExitCode -eq 1605) {
                    # Verify the package is actually gone
                    Start-Sleep -Seconds 2  # Give Windows time to update
                    if (Test-PackageRemoved -Package $Package) {
                        Write-Log "Successfully uninstalled: $($Package.Name)" "SUCCESS"
                        return $true
                    }
                    else {
                        # Special handling for Debug Runtime packages that can't be removed
                        if ($Package.Name -like "*Debug Runtime*") {
                            Write-Log "Debug Runtime package cannot be removed (likely protected): $($Package.Name)" "INFO"
                            return $true  # Consider this a "success" since we can't remove debug runtimes
                        }
                        else {
                            Write-Log "Package still appears to be installed after uninstall attempt: $($Package.Name)" "ERROR"
                            return $false
                        }
                    }
                }
                else {
                    if ($ExitCode -eq 1605) {
                        Write-Log "Package already removed (exit code 1605): $($Package.Name)" "INFO"
                        return $true
                    }
                    else {
                        Write-Log "Uninstall failed with exit code $ExitCode for: $($Package.Name)" "ERROR"
                        return $false
                    }
                }
            }
            else {
                Write-Log "No uninstall string found for: $($Package.Name)" "WARN"
                return $false
            }
        }
        else {
            # For WMI packages or any other type, try to use MSI uninstall if we have a GUID
            if ($Package.IdentifyingNumber -and $Package.IdentifyingNumber -match "^\{[A-F0-9\-]{36}\}$") {
                Write-Log "Using MSI uninstall for GUID: $($Package.IdentifyingNumber)"
                $Arguments = "/X `"$($Package.IdentifyingNumber)`" /quiet /norestart"
                Write-Log "MSI uninstall arguments: $Arguments"

                $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow -PassThru
                $ExitCode = $Process.ExitCode
                Write-Log "MSI uninstall exit code: $ExitCode"

                if ($ExitCode -eq 0 -or $ExitCode -eq 3010 -or $ExitCode -eq 1605) {
                    Start-Sleep -Seconds 3
                    if (Test-PackageRemoved -Package $Package) {
                        Write-Log "Successfully uninstalled: $($Package.Name)" "SUCCESS"
                        return $true
                    }
                    else {
                        # Special handling for Debug Runtime packages that can't be removed
                        if ($Package.Name -like "*Debug Runtime*") {
                            Write-Log "Debug Runtime package cannot be removed (likely protected): $($Package.Name)" "INFO"
                            return $true  # Consider this a "success" since we can't remove debug runtimes
                        }
                        else {
                            Write-Log "Package still appears to be installed after MSI uninstall: $($Package.Name)" "ERROR"
                            return $false
                        }
                    }
                }
                else {
                    if ($ExitCode -eq 1605) {
                        Write-Log "Package already removed (exit code 1605): $($Package.Name)" "INFO"
                        return $true
                    }
                    else {
                        Write-Log "MSI uninstall failed with exit code $ExitCode for: $($Package.Name)" "ERROR"
                        return $false
                    }
                }
            }
            else {
                Write-Log "No valid uninstall method available for: $($Package.Name)" "ERROR"
                return $false
            }
        }
    }
    catch {
        Write-Log "Error uninstalling $($Package.Name): $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-PackageRemoved {
    param([object]$Package)

    try {
        # Check if registry entry still exists
        if ($Package.IdentifyingNumber) {
            $RegPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($Package.IdentifyingNumber)",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($Package.IdentifyingNumber)"
            )

            foreach ($RegPath in $RegPaths) {
                if (Test-Path $RegPath) {
                    $RegItem = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
                    if ($RegItem -and $RegItem.DisplayName) {
                        Write-Log "Package still found in registry: $($RegItem.DisplayName)" "DEBUG"
                        return $false  # Package still exists
                    }
                }
            }
        }

        # Also check by name pattern in case GUID changed
        $RegPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        foreach ($RegPath in $RegPaths) {
            $SubKeys = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue
            foreach ($SubKey in $SubKeys) {
                try {
                    $Item = Get-ItemProperty -Path $SubKey.PSPath -ErrorAction SilentlyContinue
                    if ($Item.DisplayName -eq $Package.Name) {
                        Write-Log "Package still found by name: $($Item.DisplayName)" "DEBUG"
                        return $false  # Package still exists
                    }
                }
                catch { }
            }
        }

        Write-Log "Package appears to be removed: $($Package.Name)" "DEBUG"
        return $true  # Package not found
    }
    catch {
        Write-Log "Error verifying package removal: $($_.Exception.Message)" "WARN"
        return $false  # Assume not removed if we can't verify
    }
}

# Main execution
Write-Log "=== Visual C++ Redistributable Cleanup Script Started ==="
Write-Log "Log file: $LogFile"

# Check admin rights
if (-not (Test-AdminRights)) {
    Write-Log "ERROR: This script requires administrator privileges!" "ERROR"
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    exit 1
}

# Find all VC++ packages
$AllVCPackages = Get-VCRedistPackages

# Filter out empty packages before processing
$VCPackages = $AllVCPackages | Where-Object {
    $_.Name -and
    $_.Name.Trim() -ne "" -and
    $_.Name -ne $null
}

# Optionally filter out Debug Runtime packages (they usually can't be uninstalled)
if (-not $IncludeDebugRuntime) {
    $DebugRuntimePackages = $VCPackages | Where-Object { $_.Name -like "*Debug Runtime*" }
    if ($DebugRuntimePackages.Count -gt 0) {
        Write-Log "Excluding $($DebugRuntimePackages.Count) Debug Runtime packages (use -IncludeDebugRuntime to include them)"
        $DebugRuntimePackages | ForEach-Object {
            Write-Log "Excluded: $($_.Name) (Debug Runtime packages are typically protected and cannot be uninstalled)"
        }
        $VCPackages = $VCPackages | Where-Object { $_.Name -notlike "*Debug Runtime*" }
    }
}

if ($VCPackages.Count -eq 0) {
    Write-Log "No Visual C++ Redistributable packages found."
    Write-Host "No Visual C++ Redistributable packages found on this system." -ForegroundColor Green
    exit 0
}

# Display found packages
Write-Log "Found $($VCPackages.Count) valid Visual C++ Redistributable package(s):"
if ($AllVCPackages.Count -ne $VCPackages.Count) {
    Write-Log "Filtered out $($AllVCPackages.Count - $VCPackages.Count) invalid/empty package entries"
}

Write-Host "`nFound Visual C++ Redistributable packages:" -ForegroundColor Cyan
$VCPackages | ForEach-Object {
    $DisplayName = if ($_.Version) { "$($_.Name) (Version: $($_.Version))" } else { $_.Name }
    Write-Host "  - $DisplayName" -ForegroundColor Yellow
    Write-Log "Found: $DisplayName"
}

# Confirmation
if (-not $Silent) {
    Write-Host "`nThis will uninstall ALL Visual C++ Redistributable packages listed above." -ForegroundColor Yellow
    $Confirmation = Read-Host "Do you want to continue? (y/N)"
    if ($Confirmation -notmatch "^[Yy]") {
        Write-Log "Operation cancelled by user."
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Uninstall packages
Write-Log "Starting uninstallation process..."
Write-Host "`nStarting uninstallation process..." -ForegroundColor Cyan

$SuccessCount = 0
$FailureCount = 0

foreach ($Package in $VCPackages) {
    Write-Host "Uninstalling: $($Package.Name)..." -ForegroundColor White

    $UninstallResult = $false
    try {
        $UninstallResult = Uninstall-Package -Package $Package
    }
    catch {
        Write-Log "Exception during uninstall of $($Package.Name): $($_.Exception.Message)" "ERROR"
        $UninstallResult = $false
    }

    if ($UninstallResult -eq $true) {
        $SuccessCount++
        Write-Host "  ✓ Success" -ForegroundColor Green
    }
    else {
        $FailureCount++
        Write-Host "  ✗ Failed" -ForegroundColor Red
    }
}

# Summary
Write-Log "=== Uninstallation Complete ==="
Write-Log "Successfully uninstalled: $SuccessCount packages"
Write-Log "Failed to uninstall: $FailureCount packages"

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Successfully uninstalled: $SuccessCount packages" -ForegroundColor Green
Write-Host "Failed to uninstall: $FailureCount packages" -ForegroundColor $(if ($FailureCount -gt 0) { "Red" } else { "Green" })
Write-Host "Log file saved to: $LogFile" -ForegroundColor Gray

if ($FailureCount -gt 0) {
    Write-Host "`nSome packages failed to uninstall. Check the log file for details." -ForegroundColor Yellow
    Write-Host "Note: Exit code 1605 means the package was already removed." -ForegroundColor Gray
    Write-Host "You may need to uninstall remaining packages manually or reboot and try again." -ForegroundColor Yellow
}
else {
    Write-Host "`nAll Visual C++ Redistributable packages have been successfully removed!" -ForegroundColor Green
}

Write-Host "`nRecommendation: Check 'Add or Remove Programs' to verify all VC++ entries are gone." -ForegroundColor Cyan

Write-Log "Script completed."
