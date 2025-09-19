# 🖼️ Secure Image Downloader

A secure Python tool for downloading images from the web.  
This script focuses on **safety, duplicate prevention, and convenience** while fetching images.  

It includes:
- ✅ Domain blocking for unsafe sites  
- ✅ File size limit checks (default: 50MB)  
- ✅ Duplicate prevention via SHA-256 hashing  
- ✅ Safe filename generation  
- ✅ Batch download support  
- ✅ Logging to both console & `download_log.txt`  

---

## 🚀 Features
- Downloads images securely from HTTPS URLs (warns on non-HTTPS).
- Blocks known suspicious domains (`malware.com`, `suspicious-site.org` by default).
- Skips duplicate images using file hashes.
- Limits downloads to **50MB per file**.
- Supports multiple image formats: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.webp`, `.tiff`.
- Saves logs to `download_log.txt` for review.

---

## 📦 Installation

1. Clone the repository or download the script.
2. Install dependencies:

```bash
pip install requests

