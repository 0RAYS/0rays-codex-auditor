# Go (Non-Web/Server) Security Code Audit Skill (Vulnerability Hunting & Bug Finding)

## 1) Objective & Scope
**Goal:** Systematically find security vulnerabilities, reliability bugs, and misuse of Go runtime/library features in **non-web/server** Go programs (CLI tools, agents, desktop apps, libraries, batch jobs, file/network utilities).

**Primary attack surfaces (typical for non-server Go):**
- CLI arguments and flags
- Environment variables
- Config files (YAML/JSON/TOML/INI), `.env`
- Local file formats (archives, media, custom binary formats)
- IPC (pipes, Unix sockets), plugins, shared folders
- Outbound network clients (HTTP client, gRPC client) even if not hosting a server
- Update mechanisms (self-update, downloads, integrity checks)

**Key risk categories:**
- Command execution / injection
- Path traversal and filesystem race conditions
- Insecure deserialization / parsing bombs (zip bombs, decompression)
- Credential/secret leakage (logs, panic, error messages, core dumps)
- TLS/cert validation mistakes (client-side)
- Concurrency bugs leading to corruption/DoS
- Supply-chain risks (modules, `go:embed`, plugins)

---

## 2) Required Tooling & Environment

### Go Toolchain
- Go version pinned (prefer `go.mod` with explicit version)
- Build with reproducibility awareness (modules, `GONOSUMDB`, `GOPROXY` policy)

### Static Analysis
- `go vet` (baseline)
- `staticcheck` (high signal)
- `govulncheck` (known vulns in deps)
- Optional linters via `golangci-lint` (curated set only; avoid noise)

### Fuzzing & Testing
- Go native fuzzing (`go test -fuzz=...`) for parsers/decoders
- Property-based testing (e.g., `testing/quick`) where suitable

### Dependency & Binary Inspection
- `go list -m all`, `go mod graph`
- `go env -json`
- SBOM generation if required (e.g., Syft)

---

## 3) Threat Modeling Quick Pass (Non-Server Focus)
1. **Enumerate inputs**: argv, env, stdin, files, network responses, plugins.
2. **Map trust boundaries**:
   - Untrusted file content → parser → filesystem writes
   - Untrusted network response → parsing → command execution / file writes
3. **Assets**:
   - Local filesystem integrity
   - Credentials/tokens, API keys
   - Update channel integrity
4. **Security objectives**:
   - Prevent arbitrary code execution (command exec, plugin load)
   - Prevent data exfiltration (logs, temp files, permissions)
   - Avoid DoS by resource exhaustion (memory, CPU, disk)

Deliverable: a short diagram/list of inputs → sensitive sinks.

---

## 4) Manual Code Review Checklist (Go Hotspots)

### 4.1 Command Execution & Argument Injection
High-risk usage:
- `os/exec.Command("sh","-c", ...)`
- Building command strings by concatenation
- Passing untrusted args that change behavior (e.g., `--output=/etc/...`)

Audit actions:
- Prefer `exec.Command(name, arg1, arg2...)` with strict arg construction.
- Avoid shells unless necessary; if unavoidable, robust escaping and allowlist.
- Ensure environment passed to subprocess is controlled (`Cmd.Env`).

Search:
```bash
rg -n "exec\\.Command\\(|CommandContext\\(|sh\\s*-c|bash\\s*-c" .
```

### 4.2 Filesystem: Path Traversal, Unsafe Writes, and TOCTOU
Common issues:
- `filepath.Join(base, user)` without cleaning + verifying prefix
- Archive extraction (`zip`, `tar`) without validating entry paths (`../`, absolute paths)
- Symlink attacks when writing into attacker-controlled directories
- Unsafe temp files (`/tmp` style): use `os.CreateTemp`, `os.MkdirTemp`

Audit actions:
- Canonicalize and enforce directory containment:
  - `clean := filepath.Clean(p)`
  - reject absolute paths and `..`
  - after join, verify `strings.HasPrefix(resolved, base+string(os.PathSeparator))`
- Use `O_EXCL` patterns where relevant; avoid following symlinks where possible.
- Set file permissions explicitly (`Chmod`) and consider `umask` behavior.

Search:
```bash
rg -n "os\\.OpenFile\\(|ioutil\\.WriteFile\\(|os\\.WriteFile\\(|MkdirAll\\(|filepath\\.Join\\(|filepath\\.Clean\\(" .
rg -n "archive/tar|archive/zip" .
```

### 4.3 Parsing & Resource Exhaustion (Non-Web DoS)
Go is memory-safe, but parsers can be abused:
- `io.ReadAll` on unbounded input
- `json.Unmarshal` on huge payloads
- regex catastrophic backtracking (`regexp` is RE2 and safe from backtracking, but huge inputs still DoS)
- decompression bombs (`gzip`, `zlib`, `zip`)

Audit actions:
- Add explicit limits:
  - `io.LimitReader`, `http.MaxBytesReader` (if any client reads), bounded buffers
- Stream where possible (`json.Decoder`) and cap token sizes.
- When extracting archives, limit:
  - number of entries
  - total uncompressed size
  - per-file size

Search:
```bash
rg -n "io\\.ReadAll\\(|ioutil\\.ReadAll\\(|json\\.Unmarshal\\(|xml\\.Unmarshal\\(" .
rg -n "gzip\\.NewReader|zlib\\.NewReader|zip\\.NewReader" .
```

### 4.4 Unsafe Deserialization / Gob / YAML Pitfalls
Risk areas:
- `encoding/gob` across trust boundary (type confusion / unexpected allocations)
- YAML parsing with surprising types (depending on library)
- `encoding/json` into `map[string]any` then type assertions without checks

Audit actions:
- Prefer strict schemas and typed structs.
- Validate after decode: ranges, lengths, allowed values.
- Avoid deserializing directly into interface-rich structures if input is untrusted.

Search:
```bash
rg -n "encoding/gob|yaml\\.Unmarshal|map\\[string\\]any|interface\\{\\}" .
```

### 4.5 TLS & Crypto Misuse (Client-Side)
Common mistakes in non-server tools:
- `InsecureSkipVerify: true`
- Not verifying hostnames / pins
- Using weak randomness or nonces
- Rolling custom crypto

Audit actions:
- For TLS clients:
  - require verification by default
  - if pinning is used, implement correctly with rotation strategy
- Use `crypto/rand` for secrets; avoid `math/rand` for security.

Search:
```bash
rg -n "InsecureSkipVerify\\s*:\\s*true|tls\\.Config|crypto/tls" .
rg -n "math/rand|crypto/rand" .
```

### 4.6 Concurrency & Goroutine Leaks
Even in CLI tools, goroutines can leak and deadlock:
- Goroutines blocked forever on channels
- Missing `context.Context` cancellation
- Unbounded worker creation
- Data races on shared variables (maps are not thread-safe)

Audit actions:
- Ensure every goroutine has:
  - a bounded lifetime
  - cancellation (`context`)
  - a completion signal (`WaitGroup`) if needed
- Guard shared state (mutex/atomic) or confine to one goroutine.
- Use `-race` routinely in tests.

Search:
```bash
rg -n "go\\s+func\\(|sync\\.WaitGroup|context\\.WithCancel|context\\.WithTimeout|select\\s*\\{" .
rg -n "map\\[.*\\].*\\{\\}" .
```

### 4.7 Logging, Panics, and Secret Leakage
Risks:
- Logging tokens/keys/passwords
- Panics dumping sensitive data
- Writing secrets to world-readable files or temp dirs

Audit actions:
- Redact secrets at log boundaries.
- Treat `fmt.Printf("%+v", cfg)` as a common leak.
- Ensure config and cache files have restrictive perms (0600/0700).

Search:
```bash
rg -n "log\\.Print|fmt\\.Print|zap\\.|zerolog\\.|panic\\(|Fatal\\(" .
rg -n "password|token|secret|apikey|Authorization" .
```

### 4.8 `unsafe`, `cgo`, and Plugin Loading
Non-web programs sometimes use `cgo` or `plugin`:
- Memory corruption possible through `unsafe`/C boundary
- ABI mismatch, lifetime bugs, pointer passing rules violated
- Loading untrusted plugins is equivalent to code execution

Audit actions:
- Minimize `unsafe` and isolate it.
- Verify `cgo` pointer rules and lifetime.
- Treat `plugin.Open` paths as sensitive; enforce allowlist and signatures if needed.

Search:
```bash
rg -n "\\bunsafe\\b|import\\s+\"C\"|cgo|plugin\\.Open" .
```

---

## 5) Go-Specific Vulnerability Patterns (Quick Recognition)

1. **Archive extraction traversal** (`zip slip`, `tar slip`)
2. **Unbounded reads** (`io.ReadAll` on attacker-controlled input)
3. **Goroutine leak / deadlock** (missing cancellation, channel misuse)
4. **Data race** (shared map/slice without sync)
5. **Command injection** (shell usage, argument confusion)
6. **Insecure TLS** (`InsecureSkipVerify`, skipping hostname checks)
7. **Secrets in logs/config dumps**
8. **Insecure temp files / permissive file modes**
9. **`unsafe`/`cgo` memory corruption**
10. **Update/download integrity failures** (no signature/hash validation)

---

## 6) Audit Workflow (Repeatable)

### Step A — Build, Test, and Baseline Runs
- `go test ./...`
- `go test -race ./...` (as applicable)
- Run the tool with representative inputs (files, configs, env).

### Step B — Static Analysis Pass
- `go vet ./...`
- `staticcheck ./...`
- `govulncheck ./...`

Triage high priority:
- command exec, path handling, TLS config, unbounded reads, unsafe/cgo.

### Step C — Manual Review by Input → Sink
For each untrusted input source:
1. Track validation and normalization steps
2. Locate sensitive sinks:
   - filesystem writes/removals
   - command execution
   - network connections
   - privilege changes (Windows services, sudo integrations, etc.)
3. Check for:
   - bounds/limits
   - canonical path checks
   - robust error handling

### Step D — Fuzzing
Target parsers and decoders:
- config parsing
- archive extraction
- custom binary formats
- protocol clients’ response parsing

Example:
```bash
go test ./... -fuzz=FuzzParseConfig -fuzztime=10m
```

### Step E — Security Regression Tests
For each fixed issue, add:
- a unit test with malicious input
- a fuzz seed that reproduces the issue
- a limit test (size caps, timeouts)

---

## 7) Finding Report Template (Go-Oriented)
- **Title:** (e.g., `PROJ007 - Zip Slip in ExtractArchive()`)
- **Severity:** Critical/High/Medium/Low
- **Location:** package/file:line, function
- **Description:** what fails and why
- **Impact:** file overwrite, code execution, data leak, DoS
- **Trigger:** input example (file name in archive, config snippet, env var)
- **Root Cause:** missing canonicalization/limits, unsafe exec, race
- **Fix Recommendation:** concrete API usage and checks
- **Regression Test:** test name / fuzz seed reference

---

## 8) Vulnerability ID Coding Scheme
**Format:** `<PROJ><NNN>`

- `<PROJ>`: first 4 characters of project name, uppercase; pad with `X` if shorter.
- `<NNN>`: 3-digit sequence starting at `001`.

Examples:
- `TOOL001`, `TOOL002`
- `ABXX001` (project “ab”)

Rules:
- Assign IDs when confirmed.
- Never reuse IDs; mark invalidated findings as **Rejected**.

---

## 9) Minimum “Done” Criteria (Non-Web Go)
- All input sources documented and reviewed end-to-end (input → parse → validate → sink)
- Static checks (`vet`, `staticcheck`, `govulncheck`) triaged; high-risk issues resolved/justified
- `-race` run performed on relevant tests or key flows
- Fuzzing executed for the top parsers/decoders; crashes triaged
- Final report includes prioritized fixes and regression tests
