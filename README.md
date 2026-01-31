# 🛡️ Universal Polyglot API Scanner v3.1

A unified, pattern-based API discovery tool supporting **5 major programming languages** through a modular scanner architecture. Now with **Docker deployment** and **Invicti DAST integration**.

## 🚀 Quick Start

### Option 1: Docker (Recommended for CI/CD)

```bash
# Build the image
docker build -t api-scanner .

# Scan your codebase
docker run --rm \
  -v $(pwd):/code:ro \
  -v $(pwd)/output:/output \
  api-scanner

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
python main.py ./test_samples
python main.py ./test_samples --export-openapi openapi.json
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
| `INVICTI_URL` | Your Invicti instance URL |
| `INVICTI_USER` | API User ID |
| `INVICTI_TOKEN` | API Token |
| `INVICTI_WEBSITE_ID` | Target Website ID |

## 🔧 CLI Usage

```bash
# Scan local directory
python main.py ./my-project

# Scan Git repository
python main.py https://github.com/user/repo.git

# Export OpenAPI spec for DAST tools
python main.py ./project --export-openapi openapi.json

# Export results to JSON
python main.py ./project --output results.json

# Verbose mode (show stack traces on errors)
python main.py ./project -v
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
🛡️ Universal Polyglot API Scanner v3.0
Python | C#/.NET | Go | Java | JavaScript/TypeScript

▶ Scanning...
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
```

## 📝 License

MIT License

---

Built with ❤️ using Python and Rich

**Universal Polyglot API Scanner v3.1** — *Discover. Document. Defend.*
