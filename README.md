# 🛡️ Universal Polyglot API Scanner v4.0

**Production-Ready** enterprise-grade API discovery tool supporting **5+ programming languages** through a modular scanner architecture...

## ✨ What's New in v4.0

| Feature | Description |
|---------|-------------|
| 🚀 **Parallel Processing** | Multi-threaded scanning for large codebases |
| 📊 **SARIF Export** | GitHub Security tab integration |
| 📋 **JUnit Export** | CI/CD test reporting |
| 🔄 **Incremental Scanning** | Only scan changed files |
| 📜 **Policy Engine** | Custom security compliance rules |
| 📈 **Prometheus Metrics** | Monitoring & alerting |
| 📝 **Audit Logging** | SIEM-compatible JSON logs |
| 🔍 **API Change Detection** | Breaking change analysis |

## 🚀 Quick Start

### Option 1: Docker (Recommended for CI/CD)

```bash
# Build the image
docker build -t api-scanner .

# Basic scan
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  api-scanner

# Parallel scan with SARIF output
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  -e SCANNER_PARALLEL=true \
  -e SCANNER_WORKERS=8 \
  api-scanner --export-sarif /output/scan.sarif --export-junit /output/scan.xml

# CI gate mode (fail on critical)
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  -e SCANNER_FAIL_ON_CRITICAL=true \
  api-scanner --fail-on-critical

# With Invicti upload
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  -e INVICTI_SYNC=true \
  -e INVICTI_URL=https://your-instance.invicti.com \
  -e INVICTI_USER=your-user-id \
  -e INVICTI_TOKEN=your-api-token \
  -e INVICTI_WEBSITE_ID=your-website-id \
  api-scanner
```

### Option 2: Local Installation

```bash
pip install -r requirements.txt

# Basic scan
python main.py ./my-project

# Parallel scan (large repos)
python main.py ./my-project --parallel --workers 8

# Incremental scan (CI/CD)
python main.py ./my-project --incremental

# Export all formats
python main.py ./my-project \
  --export-openapi openapi.json \
  --export-sarif scan.sarif \
  --export-junit scan.xml \
  -o results.json

# With policy compliance
python main.py ./my-project --policy policy.yaml --fail-on-policy

# Full audit mode
python main.py ./my-project --audit-log audit.json --metrics metrics.txt
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PolyglotScanner (Orchestrator)                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │
│   │   Python    │  │    C#/.NET  │  │     Go      │               │
│   │   Scanner   │  │   Scanner   │  │   Scanner   │               │
│   │             │  │             │  │             │               │
│   │ • Flask     │  │ • ASP.NET   │  │ • net/http  │               │
│   │ • FastAPI   │  │ • MinimalAPI│  │ • Gin       │               │
│   │ • Django    │  │ • SignalR   │  │ • Echo      │               │
│   │ • Legacy    │  │ • gRPC      │  │ • Fiber     │               │
│   │ • MCP       │  │             │  │ • Chi/Mux   │               │
│   └─────────────┘  └─────────────┘  └─────────────┘               │
│                                                                     │
│   ┌─────────────┐  ┌─────────────┐                                │
│   │    Java     │  │ JavaScript  │                                │
│   │   Scanner   │  │   Scanner   │                                │
│   │             │  │             │                                │
│   │ • Spring    │  │ • Express   │                                │
│   │ • JAX-RS    │  │ • Fastify   │                                │
│   │             │  │ • NestJS    │                                │
│   │             │  │ • MCP       │                                │
│   └─────────────┘  └─────────────┘                                │
│                                                                     │
│                    ┌─────────────────┐                             │
│                    │    Enricher     │                             │
│                    │ • Risk Scoring  │                             │
│                    │ • Auth Detection│                             │
│                    │ • PII Detection │                             │
│                    └─────────────────┘                             │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐ │
│   │                  v4.0 Enterprise Features                    │ │
│   ├─────────────────────────────────────────────────────────────┤ │
│   │ PolicyEngine    │ IncrementalScanner │ APIChangeDetector   │ │
│   │ SARIFFormatter  │ JUnitFormatter     │ AuditLogger         │ │
│   │ ScanMetrics     │ ParallelProcessing │ ConfigSystem        │ │
│   └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## 📋 Supported Languages & Frameworks

### Python
| Framework | Patterns |
|-----------|----------|
| Flask | `@app.route`, `@app.get/post/etc` |
| FastAPI | `@app.get`, `@router.post`, `APIRouter` |
| Django | `path()`, `url()`, `urlpatterns` |
| **Legacy/Custom** | `WSGIServer`, `OpenAPIRouter`, `add_api_route`, `frontend/` handlers |
| **Workers** | `argparse --kind`, Celery tasks |
| **MCP** | `@server.tool`, `@server.resource` |

### C#/.NET
| Framework | Patterns |
|-----------|----------|
| ASP.NET Controllers | `[Route]`, `[HttpGet/Post/etc]`, `ControllerBase` |
| Minimal API | `app.MapGet()`, `app.MapPost()` |
| SignalR | `MapHub<T>()` |
| gRPC | `MapGrpcService<T>()` |

### Go
| Framework | Patterns |
|-----------|----------|
| Standard Library | `http.HandleFunc`, `http.Handle` |
| Gin | `router.GET/POST/etc`, `gin.Default()` |
| Echo | `e.GET/POST/etc`, `echo.New()` |
| Fiber | `app.Get/Post/etc`, `fiber.New()` |
| Chi | `r.Get/Post/etc`, `chi.NewRouter()` |
| Gorilla Mux | `mux.HandleFunc`, `.Methods()` |
| gRPC | `pb.RegisterXxxServer` |

### Java
| Framework | Patterns |
|-----------|----------|
| Spring Boot | `@RestController`, `@RequestMapping`, `@GetMapping/PostMapping/etc` |
| Spring Security | `@PreAuthorize`, `@Secured` |
| JAX-RS | `@Path`, `@GET/@POST/etc` |

### JavaScript/TypeScript
| Framework | Patterns |
|-----------|----------|
| Express | `app.get()`, `router.post()` |
| Fastify | `fastify.get()` |
| Koa | `router.get()` |
| Hapi | `server.route()` |
| NestJS | `@Get()`, `@Controller()` |
| MCP | `setRequestHandler(ListToolsRequestSchema)` |
| GraphQL | `type Query`, `type Mutation` |

## ⚡ Performance

### Strict Ignore Patterns
The scanner aggressively skips these directories for maximum performance:

```
node_modules, venv, .venv, bin, obj, .git, target, vendor,
__pycache__, dist, build, .next, .nuxt, coverage, .vs, packages
```

## 📊 Output Columns

| Column | Description |
|--------|-------------|
| **Language** | Python, C#/.NET, Go, Java, JavaScript |
| **Framework** | Flask, ASP.NET, Gin, Spring, Express, etc. |
| **Type** | Endpoint, Tool, Resource, Worker, Handler, Config, Entry |
| **Method** | GET, POST, PUT, DELETE, PATCH, ANY, HANDLER, etc. |
| **Route/Name** | The API path or tool/resource name |
| **Auth** | PUBLIC, PRIVATE, or UNKNOWN (Shadow API) |
| **Risk** | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| **File:Line** | Source location |

## 🔍 Detection Types

| Type | Description |
|------|-------------|
| **Endpoint** | Standard REST API endpoint |
| **Tool** | MCP Tool definition |
| **Resource** | MCP Resource definition |
| **Worker** | Background worker/task (Celery, argparse CLI) |
| **Handler** | Legacy/custom handler class |
| **Config** | Framework configuration (MapControllers, etc.) |
| **Entry** | Server entry point (WSGIServer, gin.Default, etc.) |

## 🛡️ Risk Analysis

### Risk Scoring Factors
| Factor | Score |
|--------|-------|
| Admin/internal patterns | +5 |
| PII indicators (ssn, email, phone) | +4 |
| Auth/financial patterns | +3 |
| Mutation methods (DELETE, PUT, PATCH) | +1 |
| Shadow API (unknown auth) | +1 |
| Sensitive + PUBLIC | +2 |

### Risk Levels
- **CRITICAL**: Score >= 8
- **HIGH**: Score >= 5
- **MEDIUM**: Score >= 3
- **LOW**: Score >= 1
- **INFO**: Score = 0

## 📁 Project Structure

```
ApiSecurity/
├── main.py              # Universal Polyglot Scanner
├── invicti_sync.py      # Invicti DAST integration
├── entrypoint.sh        # Docker orchestrator
├── Dockerfile           # Production container
├── requirements.txt     # Dependencies
├── README.md            # This file
├── .gitlab-ci.yml       # GitLab CI template
├── .github/workflows/   # GitHub Actions template
│   └── security.yml
└── test_samples/        # Sample applications
    ├── fastapi_app.py       # FastAPI endpoints
    ├── flask_app.py         # Flask endpoints
    ├── complex_python_app.py # WSGI/Gevent/Custom
    ├── mcp_server_python.py  # Python MCP server
    ├── Controllers.cs       # .NET Controllers
    ├── Startup.cs           # .NET Startup config
    ├── go_app.go            # Go (Gin/Echo/Fiber/Mux)
    ├── SpringApp.java       # Java Spring Boot
    ├── express_app.js       # Express.js
    ├── nestjs_app.ts        # NestJS
    └── mcp_server_typescript.ts # TypeScript MCP
```

## 🐳 Docker Deployment

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TARGET_DIR` | No | `/code` | Directory to scan |
| `OUTPUT_DIR` | No | `/output` | Output directory for results |
| `SCANNER_PARALLEL` | No | `false` | Enable parallel scanning |
| `SCANNER_WORKERS` | No | `4` | Number of parallel workers |
| `SCANNER_MAX_FILE_SIZE` | No | `10` | Max file size (MB) to scan |
| `SCANNER_INCREMENTAL` | No | `false` | Enable incremental scanning |
| `SCANNER_FAIL_ON_CRITICAL` | No | `false` | Exit code 1 if critical findings |
| `SCANNER_METRICS` | No | `false` | Enable Prometheus metrics |
| `INVICTI_SYNC` | No | `false` | Enable Invicti upload |
| `DRY_RUN` | No | `false` | Preview mode (no actual upload) |
| `INVICTI_URL` | If sync | - | Invicti instance URL |
| `INVICTI_USER` | If sync | - | Invicti API User ID |
| `INVICTI_TOKEN` | If sync | - | Invicti API Token |
| `INVICTI_WEBSITE_ID` | If sync | - | Target Website ID in Invicti |

### Examples

```bash
# Basic scan
docker run --rm -v $(pwd):/code:ro -v $(pwd)/output:/output api-scanner

# Parallel scan with 8 workers
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  -e SCANNER_PARALLEL=true \
  -e SCANNER_WORKERS=8 \
  api-scanner

# CI gate mode with all exports
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  api-scanner \
    --parallel \
    --export-sarif /output/scan.sarif \
    --export-junit /output/scan.xml \
    --fail-on-critical

# Dry run (preview without upload)
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  -e INVICTI_SYNC=true \
  -e DRY_RUN=true \
  -e INVICTI_URL=https://your.invicti.com \
  api-scanner
```

## 🔗 CI/CD Integration

### GitLab CI

Add the included `.gitlab-ci.yml` to your repository and configure these CI/CD variables:

| Variable | Type | Protected | Masked |
|----------|------|-----------|--------|
| `INVICTI_URL` | Variable | ✅ | ❌ |
| `INVICTI_USER` | Variable | ✅ | ✅ |
| `INVICTI_TOKEN` | Variable | ✅ | ✅ |
| `INVICTI_WEBSITE_ID` | Variable | ✅ | ❌ |

### GitHub Actions

Copy `.github/workflows/security.yml` and configure these secrets:

| Secret | Description |
|--------|-------------|
| `DOCKER_USERNAME` | Docker Hub username |
| `DOCKER_PASSWORD` | Docker Hub access token |

## 🔧 CLI Usage

```bash
# Basic scan
python main.py ./my-project

# Scan Git repository
python main.py https://github.com/user/repo.git

# Parallel scan (for large repos)
python main.py ./project --parallel --workers 8

# Incremental scan (only changed files)
python main.py ./project --incremental --baseline .baseline.json

# Export OpenAPI spec for DAST tools
python main.py ./project --export-openapi openapi.json

# Export SARIF for GitHub Security
python main.py ./project --export-sarif scan.sarif

# Export JUnit for CI/CD
python main.py ./project --export-junit scan.xml

# Export all + JSON results
python main.py ./project \
  -o results.json \
  --export-openapi openapi.json \
  --export-sarif scan.sarif \
  --export-junit scan.xml

# Policy compliance check
python main.py ./project --policy policy.yaml --fail-on-policy

# CI gate mode (fail on critical)
python main.py ./project --fail-on-critical

# Full audit mode
python main.py ./project \
  --audit-log audit.json \
  --metrics metrics.txt

# Compare with previous scan (detect breaking changes)
python main.py ./project --compare previous-results.json

# Quiet mode (minimal output)
python main.py ./project -q -o results.json

# Verbose mode (show stack traces)
python main.py ./project -v
```

### All CLI Options

```
Usage: python main.py [OPTIONS] <target>

Output Options:
  -o, --output FILE         Output JSON file
  --export-openapi [FILE]   Export OpenAPI 3.0 spec
  --export-sarif [FILE]     Export SARIF format
  --export-junit [FILE]     Export JUnit XML
  --service-name NAME       Microservice identifier

Scan Options:
  --parallel                Enable parallel scanning
  --workers N               Number of workers (default: 4)
  --incremental             Scan only changed files
  --baseline FILE           Baseline file for incremental
  --max-file-size MB        Max file size (default: 10)
  --config FILE             Config file (JSON/YAML)

Policy & Compliance:
  --policy FILE             Security policy file
  --fail-on-critical        Exit 1 if critical findings
  --fail-on-policy          Exit 1 if policy violations

Audit & Metrics:
  --audit-log FILE          Audit log file
  --metrics FILE            Prometheus metrics file

Change Detection:
  --compare FILE            Compare with previous scan

General:
  -v, --verbose             Verbose output
  -q, --quiet               Minimal output
  --version                 Show version
```

### Invicti Sync CLI

```bash
# Upload to Invicti
export INVICTI_URL=https://your.invicti.com
export INVICTI_USER=user-id
export INVICTI_TOKEN=api-token
export INVICTI_WEBSITE_ID=website-id

python invicti_sync.py --file openapi.json

# Preview mode
python invicti_sync.py --file openapi.json --dry-run

# With diff comparison
python invicti_sync.py --file openapi.json --diff previous.json
```

## 📜 Policy Engine

Create custom security policies to enforce organizational standards:

### Example Policy File (policy.yaml)

```yaml
policies:
  - name: no-public-admin
    description: Admin endpoints must not be public
    severity: CRITICAL
    condition: "'admin' in ep.route.lower() and ep.auth_status == AuthStatus.PUBLIC"
  
  - name: no-shadow-mutation
    description: Mutation endpoints must have explicit authentication
    severity: HIGH
    condition: "ep.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and ep.auth_status == AuthStatus.UNKNOWN"
  
  - name: no-sensitive-public
    description: Sensitive data endpoints must be private
    severity: CRITICAL
    condition: "any(kw in ep.route.lower() for kw in ['password', 'token', 'secret']) and ep.auth_status == AuthStatus.PUBLIC"
  
  - name: require-auth-non-health
    description: All non-health endpoints should have auth info
    severity: MEDIUM
    condition: "ep.auth_status == AuthStatus.UNKNOWN and not any(kw in ep.route.lower() for kw in ['health', 'ping', 'ready'])"
```

### Usage

```bash
# Check compliance
python main.py ./project --policy policy.yaml

# Fail CI if violations
python main.py ./project --policy policy.yaml --fail-on-policy
```

## 📊 Output Formats

### SARIF (GitHub Security)

```bash
python main.py ./project --export-sarif scan.sarif
```

Upload to GitHub Security tab or use with `github/codeql-action/upload-sarif`.

### JUnit XML (CI/CD)

```bash
python main.py ./project --export-junit scan.xml
```

Compatible with Jenkins, GitLab CI, Azure DevOps test reporting.

### Prometheus Metrics

```bash
python main.py ./project --metrics metrics.txt
```

Output:
```
# HELP api_scan_endpoints_total Total endpoints discovered
# TYPE api_scan_endpoints_total counter
api_scan_endpoints_total{target="./project"} 87

# HELP api_scan_critical_findings Critical security findings
# TYPE api_scan_critical_findings gauge
api_scan_critical_findings{target="./project"} 3
```

## 🧩 Extending the Scanner

### Adding a New Language Scanner

```python
class RubyScanner(BaseScanner):
    @property
    def language(self) -> Language:
        return Language.RUBY  # Add to Language enum
    
    @property
    def extensions(self) -> Set[str]:
        return {".rb"}
    
    @property
    def patterns(self) -> List[PatternDef]:
        return [
            PatternDef(
                regex=r'get\s+["\']([^"\']+)["\']',
                framework="Sinatra",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            # Add more patterns...
        ]
    
    def scan_with_heuristics(self, file_path, content, lines):
        # Optional: Add Ruby-specific heuristic rules
        return []
```

Then add to the orchestrator:
```python
self.scanners[".rb"] = RubyScanner()
```

## 📈 Example Output

```
🛡️ Universal Polyglot API Scanner v4.0.0
Python | C#/.NET | Go | Java | JavaScript/TypeScript | OpenAPI | GraphQL
Production Ready: Parallel | Incremental | Policy | SARIF | Metrics

▶ Scanning... (scan_id: a1b2c3d4)
✓ Found 87 endpoints

======================================================================
╭────────────────── 📈 Analysis Results ──────────────────╮
│                                                          │
│ 📊 Scan Summary                                          │
│                                                          │
│ Total Endpoints: 87                                      │
│ Files Scanned: 12 | Skipped: 234                        │
│                                                          │
│ By Language:                                             │
│   • Python: 28                                           │
│   • C#/.NET: 24                                          │
│   • Go: 18                                               │
│   • Java: 12                                             │
│   • JavaScript: 5                                        │
│                                                          │
│ By Risk:                                                 │
│   • Critical: 3                                          │
│   • High: 8                                              │
│   • Medium: 15                                           │
│   • Low: 31                                              │
│                                                          │
│ Auth Status:                                             │
│   • Public: 12                                           │
│   • Private: 45                                          │
│   • Shadow APIs: 30                                      │
│                                                          │
╰──────────────────────────────────────────────────────────╯

┌─────────────────────────────────────────────────────────────────────────────┐
│ 🔍 Discovered API Endpoints                                                  │
├───┬──────────┬────────────┬──────────┬────────┬────────────────┬──────┬─────┤
│ # │ Language │ Framework  │ Type     │ Method │ Route/Name     │ Auth │Risk │
├───┼──────────┼────────────┼──────────┼────────┼────────────────┼──────┼─────┤
│ 1 │ C#/.NET  │ ASP.NET    │ Endpoint │ DELETE │ /admin/users   │ UNK  │CRIT │
│ 2 │ Java     │ Spring     │ Endpoint │ POST   │ /admin/reset   │ UNK  │CRIT │
│ 3 │ Go       │ Gin        │ Endpoint │ DELETE │ /admin/users   │ UNK  │HIGH │
│ 4 │ Python   │ FastAPI    │ Endpoint │ POST   │ /api/payments  │ PRIV │HIGH │
│ 5 │ Python   │ MCP        │ Tool     │ TOOL   │ execute_sql    │ UNK  │HIGH │
│...│ ...      │ ...        │ ...      │ ...    │ ...            │ ...  │...  │
└───┴──────────┴────────────┴──────────┴────────┴────────────────┴──────┴─────┘

⚠️ HIGH PRIORITY
  • [CRITICAL] C#/.NET DELETE /admin/users/{id}
    └─ admin: \badmin\b
    └─ Shadow API
  • [CRITICAL] Java POST /admin/database/reset
    └─ admin: \badmin\b

👻 Shadow APIs: 30

🚨 Policy Violations: 5
  • [HIGH] no-shadow-mutation: POST /api/auth/login
  • [HIGH] no-shadow-mutation: DELETE /admin/users/{id}

✓ Saved: results.json
✓ SARIF exported: scan.sarif
✓ JUnit exported: scan.xml

✓ Complete!
```

## 📝 License

MIT License

---

Built with ❤️ using Python and Rich

**Universal Polyglot API Scanner v4.0** — *Discover. Document. Defend.*

```
v4.0.0 - Production Ready
├── Parallel Processing (ThreadPoolExecutor)
├── SARIF 2.1.0 Export (GitHub Security)
├── JUnit XML Export (CI/CD)
├── Policy Engine (Custom compliance rules)
├── Incremental Scanning (Baseline support)
├── API Change Detection (Breaking changes)
├── Audit Logging (SIEM-compatible JSON)
├── Prometheus Metrics (Monitoring)
└── Configuration System (ENV/JSON/YAML)
```
