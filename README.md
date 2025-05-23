# Uninstall Visual C++ Redistributables

A PowerShell script to identify and uninstall all Visual C++ Redistributable packages on your system.

## ⚠️ Warning

**Use this at your own risk!** Many applications depend on these packages to function properly. Only use this if you need to clean up conflicting versions or are planning to reinstall fresh versions afterward. I've run this successfully on my own system but cannot be held responsible if anything breaks on yours. Always back up your data.

## 🔧 Requirements

- **Windows 10** or **Windows 11**
- **PowerShell 7 or later** (PowerShell 5 may work but is untested)
- **Administrator privileges**
- **PowerShell execution policy** allowing script execution (see Troubleshooting below)

## 📋 Features

- 🔍 **Comprehensive Detection**: Scans both registry and WMI for VC++ packages
- 🛡️ **Safety First**: Interactive confirmation by default
- 📝 **Detailed Logging**: Timestamped logs for all operations
- 🎯 **Smart Filtering**: Excludes protected Debug Runtime packages by default
- 🔄 **Multiple Methods**: Handles both MSI and non-MSI uninstallers
- ✅ **Verification**: Confirms successful removal after each uninstall

## 📖 Usage

```powershell
# Run with confirmation prompts (recommended)
.\Uninstall-AllVCRedist.ps1

# Run without prompts (use with caution)
.\Uninstall-AllVCRedist.ps1 -Silent

# Specify custom log directory
.\Uninstall-AllVCRedist.ps1 -LogPath "C:\Logs"

# Include protected Debug Runtime packages (unlikely to succeed)
.\Uninstall-AllVCRedist.ps1 -IncludeDebugRuntime
```

## 📊 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Silent` | Switch | `$false` | Run without confirmation prompts |
| `LogPath` | String | Current directory | Directory where log files are saved |
| `IncludeDebugRuntime` | Switch | `$false` | Include Debug Runtime packages (usually protected) |

## 📁 Log Files

The script automatically creates timestamped log files:

- **Format**: `VCRedist_Uninstall_YYYYMMDD_HHMMSS.log`
- **Location**: Specified by `-LogPath` parameter (default: script directory)
- **Content**: Detailed operation logs including errors and success messages

### Exit Codes

- **0**: Success - all packages processed
- **1**: Error - missing administrator privileges
- **3010**: Success - reboot may be required
- **1605**: Package already removed

## 🔄 After Uninstalling

1. **Check Programs List**: Verify removal in "Add or Remove Programs"
2. **Reboot if Needed**: Some packages may require a restart
3. **Reinstall if Necessary**: You can get the latest versions from
here: [Microsoft Visual C++ Redistributable latest supported downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)

## 🐛 Troubleshooting

**"Execution policy" error**:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Access denied" error**:

- Ensure PowerShell is running as Administrator
- Some packages may be protected by Windows and cannot be removed

**Packages still visible after removal**:

- Try rebooting and running the script again
- Some entries may be orphaned registry keys

## ⚖️ License

This script is licensed under the [MIT License](LICENSE).
