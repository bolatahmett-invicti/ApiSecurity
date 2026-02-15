# Security Features

## Path Security & Scan Directory Restrictions

The API Scanner includes comprehensive path validation to prevent security issues when scanning directories.

### Security Checks

The scanner automatically validates all scan paths against these security rules:

#### 1. **System Directory Protection**
Prevents scanning of critical system directories:

**Linux/macOS:**
- `/etc` - System configuration
- `/boot` - Boot files
- `/dev`, `/proc`, `/sys` - System interfaces
- `/root` - Root user home
- `/var/log` - System logs
- `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` - System binaries

**Windows:**
- `C:\Windows` - Windows system directory
- `C:\Windows\System32` - System binaries
- `C:\Program Files` - Installed programs
- `C:\Program Files (x86)`

**Result:** Scanner will refuse to scan these directories and exit with error.

#### 2. **Path Traversal Prevention**
Detects and warns about path traversal attempts:
```bash
# These will be detected and logged:
python main.py ../../etc
python main.py /workspace/../../../etc
```

**Result:** Path is resolved and validated after traversal. Logged as warning if suspicious.

#### 3. **Symbolic Link Protection**
By default, symbolic links are **not allowed** to prevent:
- Directory escaping
- Scanning unintended locations
- Following malicious symlinks

```bash
# This will fail by default:
ln -s /etc suspicious_link
python main.py suspicious_link
# Error: Symbolic links are not allowed
```

**To enable:** Set `ENABLE_SYMLINK_SCAN=true` (use with caution).

#### 4. **Allowed Directory Restrictions** (Optional)
Restrict scanning to specific base directories:

```bash
# Set allowed directories
export ALLOWED_SCAN_DIRS="/workspace,/app,/home/user/projects"

# This will succeed:
python main.py /workspace/myproject

# This will fail:
python main.py /tmp/untrusted
# Error: Path is not under allowed directories
```

**Result:** Scanner will only scan paths under configured directories.

---

## Configuration

### Environment Variables

```bash
# Restrict scan to specific directories (comma-separated)
ALLOWED_SCAN_DIRS=/workspace,/app

# Enable scanning of symbolic links (default: false)
ENABLE_SYMLINK_SCAN=true
```

### Example: Docker Deployment

**Secure deployment with restricted directories:**

```dockerfile
# Dockerfile
ENV ALLOWED_SCAN_DIRS=/workspace
WORKDIR /workspace
```

```bash
# Run with volume mount
docker run -v /host/code:/workspace api-scanner /workspace
# ✓ Allowed

docker run -v /host/code:/workspace api-scanner /etc
# ✗ Blocked - system directory

docker run -v /host/code:/workspace api-scanner /tmp
# ✗ Blocked - not in ALLOWED_SCAN_DIRS
```

### Example: CI/CD Pipeline

```yaml
# GitHub Actions
- name: Scan API
  run: |
    export ALLOWED_SCAN_DIRS="${GITHUB_WORKSPACE}"
    python main.py .
  env:
    ALLOWED_SCAN_DIRS: ${{ github.workspace }}
```

---

## Error Messages

### Security Violation
```
✗ Security Error: Cannot scan restricted system directory: /etc
```
**Solution:** Choose a different directory outside system paths.

### Symbolic Link Blocked
```
✗ Security Error: Symbolic links are not allowed: /app/link -> /etc
```
**Solution:**
- Scan the real path directly, or
- Set `ENABLE_SYMLINK_SCAN=true` if safe

### Path Not Allowed
```
✗ Security Error: Path /tmp/code is not under allowed directories: /workspace, /app
```
**Solution:**
- Move code to allowed directory, or
- Update `ALLOWED_SCAN_DIRS` configuration

---

## Audit Logging

All security violations are logged to the audit log:

```json
{
  "event": "security_violation",
  "timestamp": "2025-02-15T13:30:45",
  "error": "Cannot scan restricted system directory",
  "attempted_path": "/etc",
  "user": "developer"
}
```

Enable audit logging:
```bash
python main.py /workspace --audit-log security.log
```

---

## Best Practices

### 1. **Production Deployments**
Always set `ALLOWED_SCAN_DIRS` in production:
```bash
# Good - restricted to workspace
ALLOWED_SCAN_DIRS=/workspace,/app

# Bad - unrestricted
ALLOWED_SCAN_DIRS=
```

### 2. **Multi-Tenant Environments**
Each tenant should have their own allowed directories:
```bash
# Tenant 1
ALLOWED_SCAN_DIRS=/workspace/tenant1

# Tenant 2
ALLOWED_SCAN_DIRS=/workspace/tenant2
```

### 3. **Docker Containers**
Use volume mounts with restricted paths:
```bash
docker run \
  -v /host/code:/workspace:ro \
  -e ALLOWED_SCAN_DIRS=/workspace \
  api-scanner /workspace
```

### 4. **CI/CD Pipelines**
Lock down to repository directory:
```bash
export ALLOWED_SCAN_DIRS="${CI_PROJECT_DIR}"
```

### 5. **Symbolic Links**
Keep `ENABLE_SYMLINK_SCAN=false` unless you trust the source:
```bash
# Only enable if:
# - You control all symlinks
# - All targets are safe
# - You need to follow links (e.g., node_modules)
ENABLE_SYMLINK_SCAN=true
```

---

## Security Bypass (DO NOT DO THIS)

The following configurations **disable security** and should **never** be used in production:

```bash
# ❌ INSECURE - Disables all directory restrictions
unset ALLOWED_SCAN_DIRS

# ❌ INSECURE - Allows scanning any symlink
ENABLE_SYMLINK_SCAN=true

# ❌ INSECURE - Running as root
sudo python main.py /
```

---

## Threat Model

### What This Protects Against

✅ **Accidental system scans** - Prevents scanning `/etc`, `/boot`, etc.
✅ **Path traversal** - Detects `../../` in paths
✅ **Symlink escapes** - Blocks scanning via symbolic links
✅ **Unauthorized access** - Restricts to allowed directories only
✅ **Multi-tenant isolation** - Each tenant can only scan their directories

### What This Does NOT Protect Against

❌ **Code in allowed directory** - If malicious code is in `/workspace`, it will be scanned
❌ **Supply chain attacks** - Dependencies are not validated
❌ **Compromised LLM responses** - AI enrichment responses are trusted
❌ **Local privilege escalation** - OS-level security is not enforced

---

## Compliance

These security features help meet requirements for:

- **SOC 2** - Access control and audit logging
- **ISO 27001** - Information security management
- **PCI DSS** - Secure configuration and access control
- **OWASP** - Path traversal prevention (A01:2021)

---

## Questions?

For security concerns, contact: security@yourcompany.com

For feature requests: https://github.com/yourorg/api-scanner/issues
