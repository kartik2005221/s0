# s0 — Windows Secure File & Folder Eraser (Module 2)

**Target Authority:** NTRO — Digital Forensics & Data Sanitization  
**Supported Operating Systems:** Windows 10, Windows 11, Windows Server 2016/2019/2022  
**Supported Filesystems:** NTFS, ReFS, FAT32, exFAT

---

## 1. Forensic Engineering on Windows

Sanitizing files reliably on Microsoft Windows presents distinct architectural challenges:
1. **Alternate Data Streams (ADS):**
   - NTFS allows files to attach multiple data streams (e.g. `file.txt:Zone.Identifier` or hidden payloads).
   - Standard file deletion only unlinks the primary stream. s0 enumerates and overwrites known and discovered ADS before deletion.
2. **Win32 File Attributes & Locking:**
   - Files marked with `FILE_ATTRIBUTE_READONLY` or `FILE_ATTRIBUTE_HIDDEN` fail standard deletion. s0 invokes `SetFileAttributesW(FILE_ATTRIBUTE_NORMAL)` and unlocks write permissions.
3. **Hardware Disk Cache Flushing:**
   - Overwrites held in the Windows File System Cache may not reach physical non-volatile storage if power is cut. s0 invokes Win32 `FlushFileBuffers` through `msvcrt.get_osfhandle`.
4. **Copy-on-Write (CoW) on ReFS:**
   - Microsoft Resilient File System (ReFS) allocates new clusters on overwrite. s0 queries `GetVolumeInformationW` and explicitly logs CoW caveats in the sanitization certificate.
5. **Metadata & Directory Obfuscation:**
   - Inode/MFT timestamps are zeroed to epoch (0), and directory entries are scrambled with cryptographically secure hexadecimal tokens prior to calling Win32 `DeleteFileW`.

---

## 2. Usage

### Command Prompt (`cmd.exe`):
```cmd
windows\s0-eraser.bat C:\Sensitive\evidence.docx 1 zero
```

### PowerShell:
```powershell
.\windows\s0-eraser.ps1 -Targets "C:\Sensitive\ConfidentialFolder" -Passes 1 -Pattern zero
```

### Python Direct:
```bash
python windows/s0_eraser.py --targets C:\TargetFile.pdf --passes 1 --pattern zero --out-dir .\reports
```
