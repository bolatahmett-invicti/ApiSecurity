#!/usr/bin/env python3
"""
Invicti Platform API Inventory Sync - CI/CD Integration Bridge
===============================================================
Uploads auto-discovered API endpoints to Invicti Platform API Inventory.

This script is designed to run in CI/CD pipelines (GitLab CI, Jenkins, GitHub Actions)
immediately after the Universal Polyglot API Scanner generates an OpenAPI spec.

Features:
  - Smart Diff: Compare current vs previous scan to highlight new endpoints
  - Secure: All credentials via environment variables
  - CI-Friendly: Clear console output for pipeline logs
  - Dry-Run Mode: Test without uploading
  - API Inventory Integration: Track APIs as assets across organization

Environment Variables (Required):
  - INVICTI_URL: Base URL (e.g., https://platform.invicti.com or https://api.invicti.com)
  - INVICTI_USER: API User ID
  - INVICTI_TOKEN: API Token
  - INVICTI_TEAM_ID: Team ID (optional, for multi-tenant environments)

Environment Variables (Optional):
  - GITHUB_REPOSITORY: GitHub repository name (auto-detected)
  - CI_PROJECT_NAME: GitLab project name (auto-detected)
  - SERVICE_NAME: Service name override

Usage:
  python invicti_sync.py --file openapi.json --service-name payment-service
  python invicti_sync.py --file openapi.json --service-name user-api --diff previous.json
  python invicti_sync.py --file openapi.json --service-name gateway --dry-run

Author: Principal Security Engineer
"""

import os
import sys
import json
import argparse
import base64
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime

# =============================================================================
# DEPENDENCY CHECK
# =============================================================================
try:
    import requests
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
      - INVICTI_URL: Base URL of Invicti Platform instance
      - INVICTI_USER: API User ID
      - INVICTI_TOKEN: API Token
      - INVICTI_TEAM_ID: Team ID (optional)
    """
    
    REQUIRED_VARS = [
        ("INVICTI_URL", "Base URL (e.g., https://platform.invicti.com)"),
        ("INVICTI_USER", "API User ID"),
        ("INVICTI_TOKEN", "API Token"),
    ]
    
    OPTIONAL_VARS = [
        ("INVICTI_TEAM_ID", "Team ID for multi-tenant environments"),
    ]
    
    def __init__(self):
        self.url: str = ""
        self.user: str = ""
        self.token: str = ""
        self.team_id: Optional[str] = None
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
            print("  export INVICTI_URL='https://platform.invicti.com'")
            print("  export INVICTI_USER='your-api-user-id'")
            print("  export INVICTI_TOKEN='your-api-token'")
            print("  export INVICTI_TEAM_ID='your-team-id'  # Optional")
            sys.exit(1)
        
        self.url = os.getenv("INVICTI_URL", "").rstrip("/")
        self.user = os.getenv("INVICTI_USER", "")
        self.token = os.getenv("INVICTI_TOKEN", "")
        self.team_id = os.getenv("INVICTI_TEAM_ID", "").strip() or None
    
    def get_basic_auth_header(self) -> str:
        """Get Base64 encoded Basic Auth header value."""
        credentials = f"{self.user}:{self.token}"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        return f"Basic {encoded}"
    
    def __repr__(self) -> str:
        return f"Config(url={self.url}, user={self.user[:4]}***, team_id={self.team_id})"


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
# INVICTI API INVENTORY CLIENT
# =============================================================================
class InvictiClient:
    """
    Invicti Platform API Inventory Client.
    
    Handles authentication and API interactions for uploading
    discovered endpoints to the API Inventory feature.
    """
    
    # Invicti Platform API Inventory endpoints
    ENDPOINTS = {
        # Import API definition file
        "import_api": "/api/v1/api-inventory/definitions/import",
        # List APIs in inventory
        "list_apis": "/api/v1/api-inventory/definitions",
        # Get specific API definition
        "get_api": "/api/v1/api-inventory/definitions/{id}",
        # Update existing API definition
        "update_api": "/api/v1/api-inventory/definitions/{id}",
        # Health check
        "health": "/api/v1/health",
    }
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": config.get_basic_auth_header(),
            "Accept": "application/json",
            "User-Agent": "UniversalPolyglotScanner/3.1 InvictiAPIInventorySync/2.0",
        })
        
        # Add team ID header if provided
        if config.team_id:
            self.session.headers["X-Team-Id"] = config.team_id
    
    def verify_connection(self) -> bool:
        """Verify API connection and credentials."""
        try:
            # Try to list APIs to verify authentication
            url = f"{self.config.url}{self.ENDPOINTS['list_apis']}"
            Console.info(f"Verifying connection to: {self.config.url}")
            
            response = self.session.get(url, timeout=30, params={"limit": 1})
            
            if response.status_code == 200:
                Console.success("Connected to Invicti Platform API Inventory")
                if self.config.team_id:
                    Console.info(f"Using Team ID: {self.config.team_id}")
                return True
            elif response.status_code == 401:
                Console.error("Authentication failed: Invalid credentials")
                Console.error("Check your INVICTI_USER and INVICTI_TOKEN")
                return False
            elif response.status_code == 403:
                Console.error("Authorization failed: Insufficient permissions")
                Console.error("Your API user needs 'API Inventory' permissions")
                return False
            else:
                Console.error(f"Connection failed: HTTP {response.status_code}")
                self._print_error_details(response)
                return False
                
        except requests.exceptions.Timeout:
            Console.error("Connection timeout - check INVICTI_URL")
            return False
        except requests.exceptions.ConnectionError as e:
            Console.error(f"Connection error: {e}")
            Console.error("Verify the INVICTI_URL is correct")
            return False
        except Exception as e:
            Console.error(f"Unexpected error: {e}")
            return False
    
    def upload_to_api_inventory(
        self, 
        file_path: str, 
        service_name: str,
        tags: Optional[List[str]] = None
    ) -> bool:
        """
        Upload OpenAPI specification to Invicti API Inventory.
        
        Args:
            file_path: Path to the OpenAPI spec file
            service_name: Name of the API in the inventory
            tags: Optional list of tags for categorization
        
        Returns:
            True if upload was successful, False otherwise
        """
        Console.header("📤 Uploading to Invicti API Inventory")
        
        # Verify file exists
        if not Path(file_path).exists():
            Console.error(f"File not found: {file_path}")
            return False
        
        # Read the file
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Validate it's valid JSON
            spec_data = json.loads(file_content.decode('utf-8'))
            
            # Determine the spec type
            spec_type = self._detect_spec_type(spec_data)
            
        except Exception as e:
            Console.error(f"Failed to read spec file: {e}")
            return False
        
        # Check if API already exists
        existing_api_id = self._find_existing_api(service_name)
        
        if existing_api_id:
            Console.warning(f"API '{service_name}' already exists in inventory")
            Console.info(f"Updating existing API (ID: {existing_api_id})")
            return self._update_api(existing_api_id, file_path, file_content, service_name, spec_type, tags)
        else:
            Console.info(f"Creating new API inventory entry: {service_name}")
            return self._import_new_api(file_path, file_content, service_name, spec_type, tags)
    
    def _detect_spec_type(self, spec_data: Dict[str, Any]) -> str:
        """Detect if the spec is OpenAPI 3.x or Swagger 2.x."""
        if "openapi" in spec_data:
            version = spec_data["openapi"]
            if version.startswith("3"):
                return "OpenApi3"
            return "OpenApi"
        elif "swagger" in spec_data:
            return "Swagger"
        else:
            # Default to OpenAPI
            return "OpenApi3"
    
    def _find_existing_api(self, service_name: str) -> Optional[str]:
        """Check if an API with this name already exists in the inventory."""
        try:
            url = f"{self.config.url}{self.ENDPOINTS['list_apis']}"
            response = self.session.get(
                url,
                timeout=30,
                params={"search": service_name, "limit": 100}
            )
            
            if response.status_code == 200:
                data = response.json()
                items = data.get("items", []) if isinstance(data, dict) else data
                
                # Look for exact name match
                for api in items:
                    if api.get("name", "").lower() == service_name.lower():
                        return api.get("id")
            
            return None
            
        except Exception as e:
            Console.warning(f"Could not check for existing API: {e}")
            return None
    
    def _import_new_api(
        self,
        file_path: str,
        file_content: bytes,
        service_name: str,
        spec_type: str,
        tags: Optional[List[str]] = None
    ) -> bool:
        """Import a new API definition into the inventory."""
        url = f"{self.config.url}{self.ENDPOINTS['import_api']}"
        
        try:
            # Default tags
            if tags is None:
                tags = ["auto-discovered", "ci-cd"]
            
            # Prepare multipart form data
            files = {
                "file": (Path(file_path).name, file_content, "application/json"),
            }
            
            # Prepare form data
            data = {
                "name": service_name,
                "importerType": spec_type,
                "tags": ",".join(tags),  # Some APIs expect comma-separated tags
                "description": f"Auto-discovered API from CI/CD pipeline - {datetime.now().isoformat()}",
            }
            
            # Add team ID if configured
            if self.config.team_id:
                data["teamId"] = self.config.team_id
            
            Console.info(f"Uploading to: {url}")
            Console.info(f"Service Name: {service_name}")
            Console.info(f"Spec Type: {spec_type}")
            Console.info(f"Tags: {', '.join(tags)}")
            
            # Remove Content-Type header to let requests set it with boundary
            headers = dict(self.session.headers)
            if "Content-Type" in headers:
                del headers["Content-Type"]
            
            response = self.session.post(
                url,
                files=files,
                data=data,
                headers=headers,
                timeout=120,
            )
            
            return self._handle_response(response, f"Import API '{service_name}'")
            
        except requests.exceptions.Timeout:
            Console.error("Upload timeout - file may be too large")
            return False
        except requests.exceptions.RequestException as e:
            Console.error(f"Upload failed: {e}")
            return False
    
    def _update_api(
        self,
        api_id: str,
        file_path: str,
        file_content: bytes,
        service_name: str,
        spec_type: str,
        tags: Optional[List[str]] = None
    ) -> bool:
        """Update an existing API definition in the inventory."""
        url = f"{self.config.url}{self.ENDPOINTS['update_api'].format(id=api_id)}"
        
        try:
            # Default tags
            if tags is None:
                tags = ["auto-discovered", "ci-cd", "updated"]
            
            # Prepare multipart form data
            files = {
                "file": (Path(file_path).name, file_content, "application/json"),
            }
            
            # Prepare form data
            data = {
                "name": service_name,
                "importerType": spec_type,
                "tags": ",".join(tags),
                "description": f"Auto-updated API from CI/CD pipeline - {datetime.now().isoformat()}",
            }
            
            Console.info(f"Updating at: {url}")
            
            # Remove Content-Type header to let requests set it with boundary
            headers = dict(self.session.headers)
            if "Content-Type" in headers:
                del headers["Content-Type"]
            
            response = self.session.put(
                url,
                files=files,
                data=data,
                headers=headers,
                timeout=120,
            )
            
            return self._handle_response(response, f"Update API '{service_name}'")
            
        except requests.exceptions.Timeout:
            Console.error("Update timeout - file may be too large")
            return False
        except requests.exceptions.RequestException as e:
            Console.error(f"Update failed: {e}")
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
                    if "id" in data:
                        print(f"   • API ID: {data['id']}")
                    if "name" in data:
                        print(f"   • Name: {data['name']}")
                    if "endpointsCount" in data:
                        print(f"   • Endpoints: {data['endpointsCount']}")
                    if "version" in data:
                        print(f"   • Version: {data['version']}")
                    if "message" in data:
                        print(f"   • Message: {data['message']}")
            except json.JSONDecodeError:
                pass
            
            return True
        
        elif status == 400:
            Console.error(f"{operation} failed: Bad Request (HTTP 400)")
            Console.error("The OpenAPI file may be invalid or missing required fields")
            self._print_error_details(response)
            return False
        
        elif status == 401:
            Console.error(f"{operation} failed: Unauthorized (HTTP 401)")
            Console.error("Check your INVICTI_USER and INVICTI_TOKEN")
            return False
        
        elif status == 403:
            Console.error(f"{operation} failed: Forbidden (HTTP 403)")
            Console.error("Your API user needs 'API Inventory' permissions")
            self._print_error_details(response)
            return False
        
        elif status == 404:
            Console.error(f"{operation} failed: Not Found (HTTP 404)")
            Console.error("Check your INVICTI_URL or the API may not exist")
            return False
        
        elif status == 409:
            Console.warning(f"{operation}: Conflict (HTTP 409)")
            Console.warning("API definition already exists with this name")
            self._print_error_details(response)
            return False
        
        elif status >= 500:
            Console.error(f"{operation} failed: Server Error (HTTP {status})")
            Console.error("Invicti Platform may be experiencing issues")
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
            text = response.text[:500] if response.text else "(empty response)"
            print(text)
        print("---------------------\n")


# =============================================================================
# MAIN WORKFLOW
# =============================================================================
def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Invicti API Inventory Sync - Upload discovered APIs to Invicti Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file openapi.json --service-name payment-service
  %(prog)s --file openapi.json --service-name user-api --diff previous.json
  %(prog)s --file openapi.json --service-name gateway --dry-run

Environment Variables (Required):
  INVICTI_URL         Base URL (e.g., https://platform.invicti.com)
  INVICTI_USER        API User ID
  INVICTI_TOKEN       API Token
  INVICTI_TEAM_ID     Team ID (optional, for multi-tenant)

Environment Variables (Optional):
  GITHUB_REPOSITORY   GitHub repository name (auto-detected)
  CI_PROJECT_NAME     GitLab project name (auto-detected)
  SERVICE_NAME        Service name override
        """
    )
    
    parser.add_argument(
        "--file", "-f",
        required=True,
        metavar="PATH",
        help="Path to the current OpenAPI spec file (required)"
    )
    
    parser.add_argument(
        "--service-name", "-s",
        metavar="NAME",
        help="API service name for inventory tracking (e.g., 'payment-service'). If not provided, attempts to auto-detect from CI environment."
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
        "--tags", "-t",
        metavar="TAG",
        nargs="+",
        help="Custom tags for the API (e.g., --tags production payment critical)"
    )
    
    args = parser.parse_args()
    
    # Auto-detect service name from environment if not provided
    service_name = args.service_name
    if not service_name:
        # Try various CI/CD environment variables
        service_name = (
            os.getenv("SERVICE_NAME") or  # Explicit override
            os.getenv("GITHUB_REPOSITORY", "").split("/")[-1] or  # GitHub Actions
            os.getenv("CI_PROJECT_NAME") or  # GitLab CI
            os.getenv("REPO_NAME") or  # Generic
            os.getenv("PROJECT_NAME") or  # Generic
            f"api-{datetime.now().strftime('%Y%m%d-%H%M%S')}"  # Fallback with timestamp
        )
        Console.info(f"Auto-detected service name: {service_name}")
    
    # Print banner
    Console.header("🛡️ Invicti API Inventory Sync v2.0")
    print(f"Timestamp:     {datetime.now().isoformat()}")
    print(f"Service:       {service_name}")
    print(f"File:          {args.file}")
    print(f"Diff:          {args.diff or '(none)'}")
    print(f"Dry-Run:       {args.dry_run}")
    if args.tags:
        print(f"Custom Tags:   {', '.join(args.tags)}")
    print()
    
    # Step 1: Compute diff (always)
    diff_engine = OpenAPIDiff(args.file, args.diff)
    
    if not diff_engine.load_specs():
        sys.exit(1)
    
    diff_engine.compute_diff()
    diff_engine.print_summary()
    
    # Step 2: If dry-run, stop here
    if args.dry_run:
        Console.info("Dry-run mode: Skipping upload to Invicti API Inventory")
        
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
    print(f"API User:       {config.user[:8]}...")
    if config.team_id:
        print(f"Team ID:        {config.team_id}")
    print()
    
    # Step 4: Initialize client and verify connection
    client = InvictiClient(config)
    
    if not client.verify_connection():
        Console.error("Failed to connect to Invicti Platform API")
        sys.exit(1)
    
    # Step 5: Prepare tags
    tags = ["auto-discovered", "ci-cd"]
    if args.tags:
        tags.extend(args.tags)
    
    # Step 6: Upload to API Inventory
    success = client.upload_to_api_inventory(
        args.file,
        service_name,
        tags
    )
    
    if success:
        Console.header("✅ Sync Complete")
        stats = diff_engine.get_stats()
        print(f"Service: {service_name}")
        print(f"Total endpoints: {stats['total_current']}")
        if stats["added"] > 0:
            print(f"New endpoints in this scan: {stats['added']}")
        Console.success(f"'{service_name}' is now tracked in Invicti API Inventory")
        Console.info("You can view it in the Invicti Platform UI under API Inventory")
        sys.exit(0)
    else:
        Console.header("❌ Sync Failed")
        Console.error(f"Failed to upload '{service_name}' to Invicti API Inventory")
        Console.error("Check the error details above and verify your configuration")
        sys.exit(1)


if __name__ == "__main__":
    main()
