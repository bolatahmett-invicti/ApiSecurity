#!/usr/bin/env python3
"""
Invicti (Netsparker) DAST Sync - CI/CD Integration Bridge
==========================================================
Uploads auto-discovered API endpoints to Invicti DAST platform.

This script is designed to run in CI/CD pipelines (GitLab CI, Jenkins, GitHub Actions)
immediately after the Universal Polyglot API Scanner generates an OpenAPI spec.

Features:
  - Smart Diff: Compare current vs previous scan to highlight new endpoints
  - Secure: All credentials via environment variables
  - CI-Friendly: Clear console output for pipeline logs
  - Dry-Run Mode: Test without uploading

Environment Variables (Required):
  - INVICTI_URL: Base URL (e.g., https://www.netsparkercloud.com)
  - INVICTI_USER: API User ID
  - INVICTI_TOKEN: API Token
  - INVICTI_WEBSITE_ID: Target Website ID in Invicti

Usage:
  python invicti_sync.py --file openapi.json
  python invicti_sync.py --file openapi.json --diff previous_openapi.json
  python invicti_sync.py --file openapi.json --diff previous_openapi.json --dry-run

Author: Principal Security Engineer
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime

# =============================================================================
# DEPENDENCY CHECK
# =============================================================================
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("\n❌ Missing dependency: pip install requests\n")
    sys.exit(1)

# =============================================================================
# CONSOLE OUTPUT HELPERS
# =============================================================================
class Console:
    """Simple console output with colors (ANSI escape codes)."""
    
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    
    @classmethod
    def _color(cls, text: str, color: str) -> str:
        """Apply color to text."""
        # Check if running in a terminal that supports colors
        if not sys.stdout.isatty():
            return text
        return f"{cls.COLORS.get(color, '')}{text}{cls.COLORS['reset']}"
    
    @classmethod
    def header(cls, text: str) -> None:
        """Print a header."""
        print(f"\n{cls._color('=' * 70, 'cyan')}")
        print(f"{cls._color(f'  {text}', 'bold')}")
        print(f"{cls._color('=' * 70, 'cyan')}\n")
    
    @classmethod
    def success(cls, text: str) -> None:
        """Print success message."""
        print(f"{cls._color('✅', 'green')} {cls._color(text, 'green')}")
    
    @classmethod
    def error(cls, text: str) -> None:
        """Print error message."""
        print(f"{cls._color('❌', 'red')} {cls._color(text, 'red')}")
    
    @classmethod
    def warning(cls, text: str) -> None:
        """Print warning message."""
        print(f"{cls._color('⚠️', 'yellow')} {cls._color(text, 'yellow')}")
    
    @classmethod
    def info(cls, text: str) -> None:
        """Print info message."""
        print(f"{cls._color('ℹ️', 'blue')} {cls._color(text, 'blue')}")
    
    @classmethod
    def added(cls, text: str) -> None:
        """Print added item."""
        print(f"  {cls._color('[+]', 'green')} {text}")
    
    @classmethod
    def removed(cls, text: str) -> None:
        """Print removed item."""
        print(f"  {cls._color('[-]', 'red')} {text}")
    
    @classmethod
    def unchanged(cls, text: str) -> None:
        """Print unchanged item."""
        print(f"  {cls._color('[=]', 'dim')} {text}")


# =============================================================================
# CONFIGURATION
# =============================================================================
class Config:
    """
    Configuration manager - reads from environment variables.
    
    Required Environment Variables:
      - INVICTI_URL: Base URL of Invicti instance
      - INVICTI_USER: API User ID
      - INVICTI_TOKEN: API Token
      - INVICTI_WEBSITE_ID: Target Website ID
    """
    
    REQUIRED_VARS = [
        ("INVICTI_URL", "Base URL (e.g., https://www.netsparkercloud.com)"),
        ("INVICTI_USER", "API User ID"),
        ("INVICTI_TOKEN", "API Token"),
        ("INVICTI_WEBSITE_ID", "Target Website ID in Invicti"),
    ]
    
    def __init__(self):
        self.url: str = ""
        self.user: str = ""
        self.token: str = ""
        self.website_id: str = ""
        self._load()
    
    def _load(self) -> None:
        """Load configuration from environment variables."""
        missing = []
        
        for var_name, description in self.REQUIRED_VARS:
            value = os.getenv(var_name, "").strip()
            if not value:
                missing.append(f"  • {var_name}: {description}")
        
        if missing:
            Console.error("Missing required environment variables:")
            for m in missing:
                print(m)
            print("\nPlease set these variables in your CI/CD pipeline or shell:")
            print("  export INVICTI_URL='https://www.netsparkercloud.com'")
            print("  export INVICTI_USER='your-api-user-id'")
            print("  export INVICTI_TOKEN='your-api-token'")
            print("  export INVICTI_WEBSITE_ID='your-website-id'")
            sys.exit(1)
        
        self.url = os.getenv("INVICTI_URL", "").rstrip("/")
        self.user = os.getenv("INVICTI_USER", "")
        self.token = os.getenv("INVICTI_TOKEN", "")
        self.website_id = os.getenv("INVICTI_WEBSITE_ID", "")
    
    def get_auth(self) -> HTTPBasicAuth:
        """Get HTTP Basic Auth object."""
        return HTTPBasicAuth(self.user, self.token)
    
    def __repr__(self) -> str:
        return f"Config(url={self.url}, user={self.user[:4]}***, website_id={self.website_id})"


# =============================================================================
# OPENAPI DIFF ENGINE
# =============================================================================
class OpenAPIDiff:
    """
    Smart Diff Engine for OpenAPI specifications.
    
    Compares two OpenAPI specs and identifies:
      - New endpoints (added)
      - Removed endpoints (deleted)
      - Changed methods on existing paths
    """
    
    def __init__(self, current_path: str, previous_path: Optional[str] = None):
        self.current_path = current_path
        self.previous_path = previous_path
        
        self.current_spec: Dict[str, Any] = {}
        self.previous_spec: Dict[str, Any] = {}
        
        self.added_endpoints: List[Tuple[str, str]] = []  # (method, path)
        self.removed_endpoints: List[Tuple[str, str]] = []
        self.unchanged_count: int = 0
    
    def load_specs(self) -> bool:
        """Load both OpenAPI specifications."""
        # Load current spec (required)
        try:
            with open(self.current_path, 'r', encoding='utf-8') as f:
                self.current_spec = json.load(f)
            Console.success(f"Loaded current spec: {self.current_path}")
        except FileNotFoundError:
            Console.error(f"Current spec file not found: {self.current_path}")
            return False
        except json.JSONDecodeError as e:
            Console.error(f"Invalid JSON in current spec: {e}")
            return False
        
        # Load previous spec (optional)
        if self.previous_path:
            try:
                with open(self.previous_path, 'r', encoding='utf-8') as f:
                    self.previous_spec = json.load(f)
                Console.success(f"Loaded previous spec: {self.previous_path}")
            except FileNotFoundError:
                Console.warning(f"Previous spec not found: {self.previous_path}")
                Console.info("Proceeding without diff (all endpoints treated as new)")
                self.previous_spec = {"paths": {}}
            except json.JSONDecodeError as e:
                Console.warning(f"Invalid JSON in previous spec: {e}")
                Console.info("Proceeding without diff")
                self.previous_spec = {"paths": {}}
        else:
            self.previous_spec = {"paths": {}}
        
        return True
    
    def _extract_endpoints(self, spec: Dict[str, Any]) -> Set[Tuple[str, str]]:
        """Extract all (method, path) tuples from a spec."""
        endpoints = set()
        paths = spec.get("paths", {})
        
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in methods.keys():
                # Skip non-HTTP method keys like 'parameters', 'summary', etc.
                if method.lower() in ["get", "post", "put", "delete", "patch", "head", "options", "trace"]:
                    endpoints.add((method.upper(), path))
        
        return endpoints
    
    def compute_diff(self) -> None:
        """Compute the difference between current and previous specs."""
        current_endpoints = self._extract_endpoints(self.current_spec)
        previous_endpoints = self._extract_endpoints(self.previous_spec)
        
        # Find added endpoints
        added = current_endpoints - previous_endpoints
        self.added_endpoints = sorted(list(added), key=lambda x: (x[1], x[0]))
        
        # Find removed endpoints
        removed = previous_endpoints - current_endpoints
        self.removed_endpoints = sorted(list(removed), key=lambda x: (x[1], x[0]))
        
        # Count unchanged
        unchanged = current_endpoints & previous_endpoints
        self.unchanged_count = len(unchanged)
    
    def print_summary(self) -> None:
        """Print diff summary to console for CI logs."""
        Console.header("🔍 API Endpoint Diff Summary")
        
        current_paths = self.current_spec.get("paths", {})
        previous_paths = self.previous_spec.get("paths", {})
        
        print(f"Current spec:  {len(current_paths)} paths")
        print(f"Previous spec: {len(previous_paths)} paths")
        print()
        
        # New endpoints
        if self.added_endpoints:
            Console.success(f"New Endpoints Discovered: {len(self.added_endpoints)}")
            for method, path in self.added_endpoints:
                Console.added(f"{method:7} {path}")
            print()
        else:
            Console.info("No new endpoints discovered")
            print()
        
        # Removed endpoints
        if self.removed_endpoints:
            Console.warning(f"Endpoints Removed: {len(self.removed_endpoints)}")
            for method, path in self.removed_endpoints:
                Console.removed(f"{method:7} {path}")
            print()
        
        # Summary stats
        print(f"📊 Statistics:")
        print(f"   • Added:     {len(self.added_endpoints)}")
        print(f"   • Removed:   {len(self.removed_endpoints)}")
        print(f"   • Unchanged: {self.unchanged_count}")
        print()
    
    def get_stats(self) -> Dict[str, int]:
        """Get diff statistics."""
        return {
            "added": len(self.added_endpoints),
            "removed": len(self.removed_endpoints),
            "unchanged": self.unchanged_count,
            "total_current": len(self._extract_endpoints(self.current_spec)),
        }


# =============================================================================
# INVICTI API CLIENT
# =============================================================================
class InvictiClient:
    """
    Invicti (Netsparker) API Client.
    
    Handles authentication and API interactions for uploading
    discovered endpoints to the DAST platform.
    """
    
    # Known Invicti API endpoints for different operations
    ENDPOINTS = {
        # Primary: Import links/URLs for scanning
        "import_links": "/api/1.0/website/importedlinks",
        # Alternative: Import OpenAPI/Swagger definition
        "import_definition": "/api/1.0/website/importdefinition",
        # Get website info
        "website": "/api/1.0/websites/get",
        # Verify API access
        "me": "/api/1.0/account/me",
    }
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.auth = config.get_auth()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "UniversalPolyglotScanner/3.1 InvictiSync/1.0",
        })
    
    def verify_connection(self) -> bool:
        """Verify API connection and credentials."""
        try:
            url = f"{self.config.url}{self.ENDPOINTS['me']}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                Console.success(f"Connected to Invicti as: {data.get('Email', 'Unknown')}")
                return True
            elif response.status_code == 401:
                Console.error("Authentication failed: Invalid credentials")
                return False
            elif response.status_code == 403:
                Console.error("Authorization failed: Insufficient permissions")
                return False
            else:
                Console.error(f"Connection failed: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            Console.error("Connection timeout - check INVICTI_URL")
            return False
        except requests.exceptions.ConnectionError as e:
            Console.error(f"Connection error: {e}")
            return False
        except Exception as e:
            Console.error(f"Unexpected error: {e}")
            return False
    
    def upload_openapi_spec(self, file_path: str) -> bool:
        """
        Upload OpenAPI specification to Invicti.
        
        This imports the discovered API endpoints so Invicti can scan them.
        """
        Console.header("📤 Uploading to Invicti DAST Platform")
        
        # Verify file exists
        if not Path(file_path).exists():
            Console.error(f"File not found: {file_path}")
            return False
        
        # Read the file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                spec_content = f.read()
            spec_data = json.loads(spec_content)
        except Exception as e:
            Console.error(f"Failed to read spec file: {e}")
            return False
        
        # Method 1: Try importing as OpenAPI definition
        success = self._upload_as_definition(file_path, spec_content)
        
        if not success:
            # Method 2: Fallback to importing individual links
            Console.info("Trying alternative upload method...")
            success = self._upload_as_links(spec_data)
        
        return success
    
    def _upload_as_definition(self, file_path: str, content: str) -> bool:
        """Upload as OpenAPI/Swagger definition file."""
        url = f"{self.config.url}{self.ENDPOINTS['import_definition']}"
        
        try:
            # Prepare multipart form data
            files = {
                "file": (Path(file_path).name, content, "application/json"),
            }
            data = {
                "WebsiteId": self.config.website_id,
                "ImportType": "OpenApi",  # or "Swagger"
            }
            
            Console.info(f"Uploading to: {url}")
            Console.info(f"Website ID: {self.config.website_id}")
            
            response = self.session.post(
                url,
                files=files,
                data=data,
                timeout=120,
            )
            
            return self._handle_response(response, "Definition Import")
            
        except requests.exceptions.Timeout:
            Console.error("Upload timeout - file may be too large")
            return False
        except requests.exceptions.RequestException as e:
            Console.error(f"Upload failed: {e}")
            return False
    
    def _upload_as_links(self, spec_data: Dict[str, Any]) -> bool:
        """Upload individual endpoint links."""
        url = f"{self.config.url}{self.ENDPOINTS['import_links']}"
        
        # Extract all URLs from the spec
        paths = spec_data.get("paths", {})
        if not paths:
            Console.warning("No paths found in spec to upload")
            return True
        
        # Build links list
        links = []
        for path in paths.keys():
            # Ensure path starts with /
            if not path.startswith("/"):
                path = "/" + path
            links.append(path)
        
        try:
            payload = {
                "WebsiteId": self.config.website_id,
                "Links": links,
            }
            
            Console.info(f"Uploading {len(links)} endpoint links...")
            
            response = self.session.post(
                url,
                json=payload,
                timeout=120,
            )
            
            return self._handle_response(response, "Links Import")
            
        except requests.exceptions.RequestException as e:
            Console.error(f"Upload failed: {e}")
            return False
    
    def _handle_response(self, response: requests.Response, operation: str) -> bool:
        """Handle API response and print appropriate messages."""
        status = response.status_code
        
        if status in [200, 201, 202, 204]:
            Console.success(f"{operation} successful! (HTTP {status})")
            
            # Try to parse and show response details
            try:
                data = response.json()
                if isinstance(data, dict):
                    if "ImportedLinksCount" in data:
                        print(f"   • Imported Links: {data['ImportedLinksCount']}")
                    if "Id" in data:
                        print(f"   • Import ID: {data['Id']}")
                    if "Message" in data:
                        print(f"   • Message: {data['Message']}")
            except json.JSONDecodeError:
                pass
            
            return True
        
        elif status == 400:
            Console.error(f"{operation} failed: Bad Request (HTTP 400)")
            self._print_error_details(response)
            return False
        
        elif status == 401:
            Console.error(f"{operation} failed: Unauthorized (HTTP 401)")
            Console.error("Check your INVICTI_USER and INVICTI_TOKEN")
            return False
        
        elif status == 403:
            Console.error(f"{operation} failed: Forbidden (HTTP 403)")
            Console.error("Your API user may not have permission for this operation")
            self._print_error_details(response)
            return False
        
        elif status == 404:
            Console.error(f"{operation} failed: Not Found (HTTP 404)")
            Console.error("Check your INVICTI_URL and INVICTI_WEBSITE_ID")
            return False
        
        elif status >= 500:
            Console.error(f"{operation} failed: Server Error (HTTP {status})")
            Console.error("Invicti server may be experiencing issues")
            self._print_error_details(response)
            return False
        
        else:
            Console.error(f"{operation} failed: HTTP {status}")
            self._print_error_details(response)
            return False
    
    def _print_error_details(self, response: requests.Response) -> None:
        """Print error response details for debugging."""
        print("\n--- Error Details ---")
        try:
            data = response.json()
            print(json.dumps(data, indent=2))
        except json.JSONDecodeError:
            print(response.text[:500] if response.text else "(empty response)")
        print("---------------------\n")


# =============================================================================
# MAIN WORKFLOW
# =============================================================================
def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Invicti DAST Sync - Upload discovered APIs to Invicti",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file openapi.json
  %(prog)s --file openapi.json --diff previous.json
  %(prog)s --file openapi.json --diff previous.json --dry-run

Environment Variables (Required):
  INVICTI_URL         Base URL (e.g., https://www.netsparkercloud.com)
  INVICTI_USER        API User ID
  INVICTI_TOKEN       API Token
  INVICTI_WEBSITE_ID  Target Website ID
        """
    )
    
    parser.add_argument(
        "--file", "-f",
        required=True,
        metavar="PATH",
        help="Path to the current OpenAPI spec file (required)"
    )
    
    parser.add_argument(
        "--diff", "-d",
        metavar="PATH",
        help="Path to the previous OpenAPI spec for comparison (optional)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform diff analysis but skip actual upload"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--service-name", "-s",
        metavar="NAME",
        help="Microservice identifier for logging (e.g., 'payment-service')"
    )
    
    args = parser.parse_args()
    
    # Print banner
    Console.header("🛡️ Invicti DAST Sync v1.0")
    print(f"Timestamp: {datetime.now().isoformat()}")
    if args.service_name:
        print(f"Service:   {args.service_name}")
    print(f"File:      {args.file}")
    print(f"Diff:      {args.diff or '(none)'}")
    print(f"Dry-Run:   {args.dry_run}")
    print()
    
    # Step 1: Compute diff (always)
    diff_engine = OpenAPIDiff(args.file, args.diff)
    
    if not diff_engine.load_specs():
        sys.exit(1)
    
    diff_engine.compute_diff()
    diff_engine.print_summary()
    
    # Step 2: If dry-run, stop here
    if args.dry_run:
        Console.info("Dry-run mode: Skipping upload to Invicti")
        
        # Exit with appropriate code based on new endpoints
        stats = diff_engine.get_stats()
        if stats["added"] > 0:
            Console.warning(f"⚠️ {stats['added']} new endpoints would be uploaded")
        
        Console.success("Dry-run complete")
        sys.exit(0)
    
    # Step 3: Load configuration (validates env vars)
    Console.header("🔐 Loading Configuration")
    config = Config()
    print(f"Invicti URL:    {config.url}")
    print(f"Website ID:     {config.website_id}")
    print(f"API User:       {config.user[:8]}...")
    print()
    
    # Log service context for microservices environments
    if args.service_name:
        Console.info(f"Syncing [{args.service_name}] to Invicti...")
    
    # Step 4: Initialize client and verify connection
    client = InvictiClient(config)
    
    if not client.verify_connection():
        Console.error("Failed to connect to Invicti API")
        sys.exit(1)
    
    # Step 5: Upload the spec
    success = client.upload_openapi_spec(args.file)
    
    if success:
        Console.header("✅ Sync Complete")
        stats = diff_engine.get_stats()
        if args.service_name:
            print(f"Service: {args.service_name}")
        print(f"Total endpoints uploaded: {stats['total_current']}")
        if stats["added"] > 0:
            print(f"New endpoints in this scan: {stats['added']}")
        Console.success("Invicti DAST can now scan the discovered APIs")
        sys.exit(0)
    else:
        Console.header("❌ Sync Failed")
        Console.error("Failed to upload OpenAPI spec to Invicti")
        Console.error("Check the error details above and verify your configuration")
        sys.exit(1)


if __name__ == "__main__":
    main()
