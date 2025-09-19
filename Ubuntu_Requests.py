import requests
import os
import hashlib
import logging
from urllib.parse import urlparse
from pathlib import Path
import time
from typing import List, Set, Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('download_log.txt'),
        logging.StreamHandler()
    ]
)

class SecureImageDownloader:
    def __init__(self, download_dir: str = "Fetched_Images"):
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(exist_ok=True)
        self.downloaded_hashes: Set[str] = set()
        self.load_existing_hashes()
        
        # Security settings
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit
        self.allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff'}
        self.blocked_domains = {'malware.com', 'suspicious-site.org'}  # Add known bad domains
        
    def load_existing_hashes(self):
        """Load hashes of already downloaded files to prevent duplicates"""
        hash_file = self.download_dir / "file_hashes.txt"
        if hash_file.exists():
            with open(hash_file, 'r') as f:
                self.downloaded_hashes = set(line.strip() for line in f if line.strip())
    
    def save_file_hash(self, file_hash: str):
        """Save file hash to prevent future duplicates"""
        hash_file = self.download_dir / "file_hashes.txt"
        with open(hash_file, 'a') as f:
            f.write(f"{file_hash}\n")
        self.downloaded_hashes.add(file_hash)
    
    def calculate_file_hash(self, content: bytes) -> str:
        """Calculate SHA-256 hash of file content"""
        return hashlib.sha256(content).hexdigest()
    
    def validate_url(self, url: str) -> bool:
        """Validate URL for security concerns"""
        try:
            parsed = urlparse(url)
            
            # Check if domain is blocked
            if parsed.netloc.lower() in self.blocked_domains:
                logging.warning(f"Blocked domain detected: {parsed.netloc}")
                return False
                
            # Check if URL uses HTTPS (preferred for security)
            if parsed.scheme != 'https':
                logging.warning(f"Non-HTTPS URL detected: {url}")
                # Don't block, but warn user
                
            return True
        except Exception as e:
            logging.error(f"URL validation error: {e}")
            return False
    
    def validate_http_headers(self, response: requests.Response) -> bool:
        """Validate HTTP headers before saving content"""
        try:
            # Check content type
            content_type = response.headers.get('content-type', '').lower()
            if not any(ext in content_type for ext in ['image/', 'application/octet-stream']):
                logging.warning(f"Unexpected content type: {content_type}")
                return False
            
            # Check content length
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.max_file_size:
                logging.error(f"File too large: {content_length} bytes")
                return False
            
            # Check for suspicious headers
            suspicious_headers = ['x-powered-by', 'server']
            for header in suspicious_headers:
                if header in response.headers:
                    logging.info(f"Server info: {header}: {response.headers[header]}")
            
            # Check for security headers
            security_headers = ['x-content-type-options', 'x-frame-options', 'x-xss-protection']
            for header in security_headers:
                if header in response.headers:
                    logging.info(f"Security header present: {header}")
            
            return True
            
        except Exception as e:
            logging.error(f"Header validation error: {e}")
            return False
    
    def get_safe_filename(self, url: str, content_type: str) -> str:
        """Generate a safe filename from URL and content type"""
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        
        if not filename or '.' not in filename:
            # Determine extension from content type
            ext = '.jpg'  # default
            if 'png' in content_type:
                ext = '.png'
            elif 'gif' in content_type:
                ext = '.gif'
            elif 'webp' in content_type:
                ext = '.webp'
            elif 'bmp' in content_type:
                ext = '.bmp'
            elif 'tiff' in content_type:
                ext = '.tiff'
            
            filename = f"downloaded_image_{int(time.time())}{ext}"
        
        # Sanitize filename
        filename = "".join(c for c in filename if c.isalnum() or c in "._-")
        return filename
    
    def download_image(self, url: str) -> bool:
        """Download a single image with security checks"""
        try:
            # Validate URL
            if not self.validate_url(url):
                return False
            
            logging.info(f"Starting download: {url}")
            
            # Create session with security headers
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'image/*,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Download with streaming to check size
            response = session.get(url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Validate headers
            if not self.validate_http_headers(response):
                return False
            
            # Read content in chunks to check size
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > self.max_file_size:
                    logging.error(f"File too large during download: {len(content)} bytes")
                    return False
            
            # Check for duplicates using hash
            file_hash = self.calculate_file_hash(content)
            if file_hash in self.downloaded_hashes:
                logging.info(f"Duplicate file detected, skipping: {url}")
                return False
            
            # Generate safe filename
            content_type = response.headers.get('content-type', '')
            filename = self.get_safe_filename(url, content_type)
            filepath = self.download_dir / filename
            
            # Handle filename conflicts
            counter = 1
            original_filepath = filepath
            while filepath.exists():
                stem = original_filepath.stem
                suffix = original_filepath.suffix
                filepath = self.download_dir / f"{stem}_{counter}{suffix}"
                counter += 1
            
            # Save file
            with open(filepath, 'wb') as f:
                f.write(content)
            
            # Save hash to prevent future duplicates
            self.save_file_hash(file_hash)
            
            logging.info(f"Successfully downloaded: {filename}")
            print(f"✓ Successfully fetched: {filename}")
            print(f"✓ Image saved to {filepath}")
            
            return True
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error for {url}: {e}")
            print(f"✗ Connection error for {url}: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error for {url}: {e}")
            print(f"✗ An error occurred for {url}: {e}")
            return False
    
    def download_multiple_images(self, urls: List[str]) -> Dict[str, bool]:
        """Download multiple images with progress tracking"""
        results = {}
        total_urls = len(urls)
        
        print(f"\nStarting batch download of {total_urls} images...")
        print("=" * 50)
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{total_urls}] Processing: {url}")
            results[url] = self.download_image(url)
            
            # Add small delay to be respectful to servers
            time.sleep(0.5)
        
        # Summary
        successful = sum(results.values())
        failed = total_urls - successful
        
        print("\n" + "=" * 50)
        print(f"Download Summary:")
        print(f"✓ Successful: {successful}")
        print(f"✗ Failed: {failed}")
        print(f"📁 Files saved to: {self.download_dir.absolute()}")
        print("\nConnection strengthened. Community enriched.")
        
        return results

def get_urls_from_user() -> List[str]:
    """Get multiple URLs from user input"""
    print("Enter image URLs (one per line). Press Enter on empty line when done:")
    urls = []
    
    while True:
        url = input().strip()
        if not url:
            break
        urls.append(url)
    
    return urls

def main():
    print("Welcome to the Secure Ubuntu Image Fetcher")
    print("A tool for mindfully collecting images from the web")
    print("Now with enhanced security and batch processing!\n")
    
    downloader = SecureImageDownloader()
    
    # Get URLs from user
    urls = get_urls_from_user()
    
    if not urls:
        print("No URLs provided. Exiting.")
        return
    
    # Download all images
    downloader.download_multiple_images(urls)

if __name__ == "__main__":
    main()