#!/bin/bash
# =============================================================================
# Universal Polyglot API Scanner - Docker Entrypoint
# =============================================================================
# Orchestrates the scan-to-upload workflow:
#   1. Run API Scanner on target directory
#   2. Generate OpenAPI 3.0 specification
#   3. Optionally upload to Invicti DAST platform
#
# Environment Variables:
#   TARGET_DIR        - Directory to scan (default: /code)
#   OUTPUT_FILE       - JSON output file (default: /output/result.json)
#   OPENAPI_FILE      - OpenAPI spec file (default: /output/openapi.json)
#   INVICTI_SYNC      - Enable Invicti upload (true/false)
#   INVICTI_URL       - Invicti base URL
#   INVICTI_USER      - Invicti API user
#   INVICTI_TOKEN     - Invicti API token
#   INVICTI_WEBSITE_ID - Invicti target website ID
#   PREVIOUS_SPEC     - Previous OpenAPI spec for diff (optional)
#   DRY_RUN           - Skip actual upload (true/false)
#
# Author: Principal Security Engineer
# =============================================================================

set -e

# =============================================================================
# COLORS & LOGGING
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════${NC}\n"
}

# =============================================================================
# CONFIGURATION
# =============================================================================
TARGET_DIR="${TARGET_DIR:-/code}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
OUTPUT_FILE="${OUTPUT_FILE:-${OUTPUT_DIR}/result.json}"
OPENAPI_FILE="${OPENAPI_FILE:-${OUTPUT_DIR}/openapi.json}"
INVICTI_SYNC="${INVICTI_SYNC:-false}"
DRY_RUN="${DRY_RUN:-false}"
PREVIOUS_SPEC="${PREVIOUS_SPEC:-}"
EXIT_CODE=0

# =============================================================================
# BANNER
# =============================================================================
echo -e "${CYAN}"
cat << 'EOF'
  _   _       _                          _    ___  _____ _____ 
 | | | |_ __ (_)_   _____ _ __ ___  __ _| |  / _ \|  _  |_   _|
 | | | | '_ \| \ \ / / _ \ '__/ __|/ _` | | / /_\ \ |_| | | |  
 | |_| | | | | |\ V /  __/ |  \__ \ (_| | | |  _  |  __/  | |  
  \___/|_| |_|_| \_/ \___|_|  |___/\__,_|_| \_| |_|_|     \_/  
                                                                
  API Scanner + DAST Integration  v3.1
EOF
echo -e "${NC}"

# =============================================================================
# VALIDATE INPUTS
# =============================================================================
log_step "Step 0: Validating Configuration"

# Check target directory exists
if [ ! -d "$TARGET_DIR" ]; then
    log_error "Target directory not found: $TARGET_DIR"
    log_info "Make sure to mount your source code: docker run -v \$(pwd):/code ..."
    exit 1
fi

# Create output directory if needed
mkdir -p "$OUTPUT_DIR"

log_info "Target Directory: $TARGET_DIR"
log_info "Output Directory: $OUTPUT_DIR"
log_info "OpenAPI Output:   $OPENAPI_FILE"
log_info "Invicti Sync:     $INVICTI_SYNC"

if [ "$INVICTI_SYNC" = "true" ]; then
    if [ -z "$INVICTI_URL" ] || [ -z "$INVICTI_USER" ] || [ -z "$INVICTI_TOKEN" ] || [ -z "$INVICTI_WEBSITE_ID" ]; then
        log_warning "Invicti credentials incomplete - sync will be skipped"
        log_info "Required: INVICTI_URL, INVICTI_USER, INVICTI_TOKEN, INVICTI_WEBSITE_ID"
        INVICTI_SYNC="false"
    else
        log_info "Invicti URL:      $INVICTI_URL"
        log_info "Invicti Website:  $INVICTI_WEBSITE_ID"
    fi
fi

# =============================================================================
# STEP 1: RUN API SCANNER
# =============================================================================
log_step "Step 1: Running Universal Polyglot API Scanner"

SCANNER_CMD="python /app/main.py \"$TARGET_DIR\" --export-openapi \"$OPENAPI_FILE\""

if [ -n "$OUTPUT_FILE" ]; then
    SCANNER_CMD="$SCANNER_CMD -o \"$OUTPUT_FILE\""
fi

log_info "Executing: $SCANNER_CMD"
echo ""

if eval $SCANNER_CMD; then
    log_success "API Scan completed successfully"
    
    # Check if OpenAPI file was created
    if [ -f "$OPENAPI_FILE" ]; then
        ENDPOINT_COUNT=$(python -c "import json; f=open('$OPENAPI_FILE'); d=json.load(f); print(len(d.get('paths', {})))" 2>/dev/null || echo "0")
        log_success "Generated OpenAPI spec with $ENDPOINT_COUNT paths"
    else
        log_error "OpenAPI file was not created"
        exit 1
    fi
else
    log_error "API Scan failed"
    exit 1
fi

# =============================================================================
# STEP 2: INVICTI SYNC (Optional)
# =============================================================================
if [ "$INVICTI_SYNC" = "true" ]; then
    log_step "Step 2: Syncing to Invicti DAST Platform"
    
    SYNC_CMD="python /app/invicti_sync.py --file \"$OPENAPI_FILE\""
    
    # Add diff file if specified
    if [ -n "$PREVIOUS_SPEC" ] && [ -f "$PREVIOUS_SPEC" ]; then
        SYNC_CMD="$SYNC_CMD --diff \"$PREVIOUS_SPEC\""
        log_info "Comparing with previous spec: $PREVIOUS_SPEC"
    fi
    
    # Add dry-run flag if specified
    if [ "$DRY_RUN" = "true" ]; then
        SYNC_CMD="$SYNC_CMD --dry-run"
        log_warning "Dry-run mode enabled - upload will be skipped"
    fi
    
    log_info "Executing: $SYNC_CMD"
    echo ""
    
    if eval $SYNC_CMD; then
        if [ "$DRY_RUN" = "true" ]; then
            log_success "Invicti Sync dry-run completed"
        else
            log_success "APIs uploaded to Invicti successfully"
        fi
    else
        log_error "Invicti Sync failed"
        EXIT_CODE=1
    fi
else
    log_step "Step 2: Invicti Sync (Skipped)"
    log_info "Set INVICTI_SYNC=true to enable automatic upload"
fi

# =============================================================================
# SUMMARY
# =============================================================================
log_step "Scan Complete"

echo -e "📊 ${BOLD}Output Files:${NC}"
if [ -f "$OPENAPI_FILE" ]; then
    echo -e "   • OpenAPI Spec: $OPENAPI_FILE"
fi
if [ -f "$OUTPUT_FILE" ]; then
    echo -e "   • JSON Report:  $OUTPUT_FILE"
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    log_success "All tasks completed successfully!"
else
    log_error "Some tasks failed - check logs above"
fi

exit $EXIT_CODE
