<div align="center">
  <img src="https://img.shields.io/badge/iOS-Security-blue?style=for-the-badge&logo=apple" alt="iOS Security">
  <img src="https://img.shields.io/badge/100%25-Client--Side-green?style=for-the-badge" alt="Client-Side">
  <img src="https://img.shields.io/badge/50+-Vulnerability%20Checks-red?style=for-the-badge" alt="50+ Checks">
</div>

<h1 align="center">🔐 IPA Auditor</h1>

<p align="center">
  <strong>Professional iOS Security Analysis Tool</strong><br>
  Analyze IPA files entirely in your browser. No uploads. Complete privacy.
</p>

<p align="center">
  <a href="https://ipaauditor.com">🌐 Live Demo</a> •
</p>

---

## 🎯 Overview

**IPA Auditor** is a powerful, browser-based static security analysis tool for iOS applications. It performs comprehensive security assessments of IPA files without uploading any data to external servers everything runs locally in your browser using JavaScript.

Perfect for:
- 🔒 Security Researchers
- 📱 iOS Developers  
- 🛡️ Penetration Testers
- 🎓 Security Auditors

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🛡️ Security Scan** | Scans all files for 50+ vulnerability patterns including ATS misconfigurations, insecure storage, weak cryptography, and hardcoded secrets |
| **💻 Binary Analysis** | Extracts strings from Mach-O executable and checks for PIE, ARC, Stack Canary, and 64-bit compilation |
| **🔐 Pattern Matching** | Searches for weak crypto usage (MD5, SHA1, DES), hardcoded secrets, API keys, and sensitive strings |
| **📁 File Inspection** | Lists all files in the IPA bundle including plists, databases, certificates, and embedded resources |
| **🔑 Permission Check** | Extracts requested entitlements and privacy permissions from the app bundle for review |
| **📂 File Explorer** | Browse all files in the IPA with hex viewer for binaries and syntax highlighting for text files |

## 🔍 Security Checks

IPA Auditor performs **50+ security checks** across multiple categories:

### 📦 Data Storage
- NSUserDefaults Insecure Storage
- CoreData Unencrypted Storage
- Realm Database Encryption
- SQLite Database Usage
- Keychain Secure Storage
- Plist File Write Operations

### 🔐 Cryptography
- Weak Hash Algorithms (MD5, SHA1)
- Weak Encryption (DES/3DES)
- ECB Mode Encryption
- Insecure Random Generator
- Hardcoded Secrets/Passwords

### 🌐 Network Security
- Insecure HTTP URLs
- SSL/TLS Validation Disabled
- SSL Pinning Implementation
- ATS Configuration Analysis
- Weak TLS Versions

### 🛡️ App Security
- Jailbreak Detection
- Anti-Debug Protection
- PIE (Position Independent Executable)
- Stack Canary Protection
- ARC (Automatic Reference Counting)

### 📱 Platform Security
- Deprecated UIWebView Usage
- JavaScript in WebView
- Custom URL Scheme Handlers
- Universal Links Validation
- Clipboard/Pasteboard Access

### ☁️ Cloud & APIs
- AWS S3 Bucket Exposure
- Firebase Database URLs
- Google API Key Exposure
- Hardcoded Tokens/Bearer

### 📊 Privacy & Tracking
- Location Tracking
- Contacts Access
- Camera/Microphone Access
- Debug Logging
- Tracker/SDK Detection

## 🚀 Usage

### Online Version
Visit [ipaauditor.com](https://ipaauditor.com) to use the tool directly in your browser.

### Local Setup
```bash
# Clone the repository
git clone https://github.com/thecybersandeep/ipaauditor.git

# Navigate to the directory
cd ipaauditor

# Open in browser (no server required)
# Simply open index.html in your browser
```

### How to Use
1. **Drop or Select** your IPA file
2. **Wait** for the analysis to complete
3. **Review** findings across different tabs:
   - **Overview**: App info, permissions, trackers
   - **Findings**: Security issues grouped by severity
   - **Binary**: Checksec results and libraries
   - **Explorer**: Browse and inspect all files

4. **Export** a detailed PDF report

## 🔒 Privacy

**Your data never leaves your device.**

- ✅ 100% client-side processing
- ✅ No server uploads
- ✅ No data collection
- ✅ No tracking
- ✅ Works offline (after initial load)

## 📊 Report Export

Generate professional PDF reports containing:
- Application metadata
- Security score
- All findings with severity levels
- Binary security checks
- Permissions analysis
- Detected trackers/SDKs
- CWE and OWASP references

## ⚠️ Disclaimer

This tool performs **pattern-based static analysis** only:

- False positives are possible
- Does not perform dynamic/runtime analysis
- Binary analysis extracts strings, not code logic

**Always have findings validated by a security professional.**

## 🛠️ Built With

- **JSZip** - ZIP file processing
- **plist.js** - Property list parsing
- **jsPDF** - PDF report generation
- **Vanilla JS** - No framework dependencies

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Star History

If you find this tool useful, please consider giving it a ⭐ on GitHub!

## 👨‍💻 Author

**Sandeep**

- GitHub: [@thecybersandeep](https://github.com/thecybersandeep)

## 🔗 Related Projects

- [ADB Auditor](https://adbauditor.com) - Android Security Analysis Tool

---

<p align="center">
  Made with ❤️ for the security community
</p>
