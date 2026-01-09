# IPA Auditor

<p align="center">
  <img src="https://ipaauditor.com/logo.svg" alt="IPA Auditor Logo" width="120">
</p>

<p align="center">
  <strong>iOS Static Security Analysis Platform</strong>
</p>

<p align="center">
  <a href="https://ipaauditor.com/">Live</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#security-checks">Security Checks</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Web-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Checks-50%2B%20OWASP%20MASVS-green?style=flat-square" alt="Security Checks">
  <img src="https://img.shields.io/badge/Privacy-100%25%20Client--Side-purple?style=flat-square" alt="Privacy">
  <img src="https://img.shields.io/github/license/thecybersandeep/ipaauditor?style=flat-square" alt="License">
</p>


<p align="center">
  <a href="https://ipaauditor.com">🌐 Live Demo</a> •
</p>

---

### Overview

IPA Auditor is a browser-based static security analysis tool for iOS applications. It performs comprehensive security scanning of IPA files based on OWASP MASVS guidelines without requiring any server-side processing or file uploads.

**🔒 100% Client-Side** - All analysis happens in your browser. Your IPA files are never uploaded anywhere.

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Static Analysis** | 50+ security checks based on OWASP MASVS guidelines |
| 🛡️ **Binary Security** | PIE, ARC, Stack Canary, and encryption verification |
| 📂 **File Explorer** | Browse IPA contents with syntax highlighting |
| 🔐 **Secret Detection** | Find hardcoded API keys, tokens, and credentials |
| 📊 **Plist Analysis** | Parse and analyze Info.plist and embedded plists |
| 📱 **Permission Audit** | Review app permissions and privacy descriptions |
| 🔗 **URL Scheme Analysis** | Identify custom URL schemes and deep links |
| 📈 **Tracker Detection** | Identify embedded analytics and tracking SDKs |
| 📄 **PDF Reports** | Export detailed security assessment reports |

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
