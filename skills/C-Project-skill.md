# C Project Security Code Audit Skill (Vulnerability Hunting & Bug Finding)

## 1) Objective & Scope
**Goal:** Systematically identify security vulnerabilities, reliability bugs, and undefined behavior in C codebases through manual review + automated tooling.

**In scope:**
- Memory safety (stack/heap overflows, UAF, double free, OOB)
- Integer issues (overflow/underflow, signedness, truncation)
- Input validation & parsing
- Concurrency (data races, deadlocks)
- Privilege/security boundaries (authz/authn, sandbox escapes)
- Cryptography misuse (if applicable)
- Build system & compiler flags that affect security

**Outputs:**
- Findings with severity, impact, PoC or reasoning, and remediation guidance
- Risk summary and prioritized fix plan

---

## 2) Required Environment & Tooling

### Compilers & Hardening Flags
- GCC/Clang (both if possible)
- Recommended baseline flags:
  - `-Wall -Wextra -Wpedantic -Wformat=2 -Wconversion -Wsign-conversion -Wshadow`
  - `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie`
  - `-fno-strict-aliasing` (case-by-case; depends on project)
  - `-O2 -g` (release-like but debuggable)

### Sanitizers (Dynamic Bug Discovery)
- AddressSanitizer (ASan): heap/stack OOB, UAF
- UndefinedBehaviorSanitizer (UBSan): overflows, invalid shifts, etc.
- MemorySanitizer (MSan): uninitialized reads (Clang)
- ThreadSanitizer (TSan): data races

Example CMake toggles (illustrative):
```bash
cmake -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" ..
make -j
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./target < testcase
```

### Static Analysis
- `clang-tidy`
- `clang-analyzer` / `scan-build`
- `cppcheck`
- Semgrep (for patterns, if used in org)

### Fuzzing (Input-Driven Vulnerability Hunting)
- libFuzzer (Clang), AFL++, honggfuzz
- Corpus minimization + crash triage with ASan/UBSan

### Debugging & Triage
- `gdb` / `lldb`
- `valgrind` (slower, good for confirmation)
- `addr2line`, `eu-addr2line`, `readelf`, `objdump`

---

## 3) Threat Modeling Quick Pass (Before Deep Dive)
1. **Identify attack surfaces**
   - Network parsers, file parsers, IPC, CLI args, environment variables
   - Deserialization, plugin systems, scripting bindings
2. **Trust boundaries**
   - Untrusted input → parser/decoder → internal state
3. **Assets**
   - Memory safety, secrets, integrity of config/state, privilege boundaries
4. **Entry points**
   - `main()`, request handlers, protocol message handlers, callbacks

Deliverable: a short map of entry points + trust boundaries to guide audit focus.

---

## 4) Manual Code Review Checklist (High-Signal Areas)

### 4.1 Memory Safety Hotspots
Look for:
- **Unbounded copies/concats:** `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`
- **Length confusion:** wrong buffer size passed to `snprintf`, `memcpy`, `strncpy`
- **Off-by-one:** terminators, loop bounds
- **Use-after-free / double free:** ownership unclear, multiple cleanup paths
- **Stack lifetime bugs:** returning pointers to stack memory

Questions to ask:
- Who owns this pointer? Who frees it?
- Are allocations checked for failure?
- Are sizes computed with correct types?

### 4.2 Integer Vulnerabilities
Common patterns:
- `int` used for sizes/lengths instead of `size_t`
- Signed/unsigned mix in comparisons (`len < 0` on `size_t` is meaningless)
- Multiplication when allocating: `malloc(n * sizeof(T))` without overflow check
- Truncation: `size_t → int`, `uint64_t → uint32_t`

Audit actions:
- Trace all size computations from input to allocation/copy.
- Ensure bounds checks happen **before** arithmetic that can overflow.

### 4.3 Input Validation & Parsing
Focus on:
- Partial reads/writes and protocol framing
- NUL byte handling in binary protocols
- UTF-8 / encoding assumptions
- Path traversal (`../`), symlinks, TOCTOU on files
- Unsafe format strings (user-controlled format)

Check:
- Are parse errors handled consistently?
- Are rejected inputs truly rejected, or partially processed?

### 4.4 Error Handling & Cleanup Paths
Typical issues:
- Ignoring return values (I/O, `malloc`, `realloc`, crypto APIs)
- Inconsistent cleanup → leaks or double frees
- `goto fail` blocks missing resets/guards

Technique:
- Review each function for a single “exit discipline” and verify resources.

### 4.5 Concurrency & Reentrancy
Look for:
- Shared global state without locking
- Callback reentrancy issues
- Incorrect lock ordering (deadlocks)
- Atomics misuse

Confirm:
- Which functions are thread-safe?
- Does the code rely on “usually single-threaded”?

### 4.6 Security Boundaries
Check for:
- Privilege drops (`setuid`, capabilities) done too late or incorrectly
- Unsafe temporary files (`/tmp` races), `mkstemp` vs `tmpnam`
- Command execution (`system`, `popen`) with untrusted input
- Environment influence (`PATH`, `LD_PRELOAD`, locale)

### 4.7 Cryptography (If Applicable)
Red flags:
- Custom crypto, ECB mode, constant IV, weak RNG
- Not checking verification results
- Timing side-channel comparisons (`strcmp` vs constant-time)

---

## 5) High-Value Code Patterns to Search (Greps / Queries)

### Dangerous APIs (Prioritize Review)
- `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`
- `scanf`, `sscanf` (especially `%s`, `%[...]`)
- `memcpy`, `memmove`, `strncpy`, `snprintf` (misuse is common)
- `realloc` (lost pointer on failure if misused)
- `atoi`, `atol` (no error reporting; prefer `strtol`)
- `system`, `popen`, `exec*` with string building
- `printf(user_input)` format string risk

### Size & Allocation Patterns
Search for:
- `malloc(` with multiplication
- casts in allocation: `(T*)malloc(...)` (not inherently wrong in C, but can hide missing include)
- `sizeof(pointer)` used instead of `sizeof(*pointer)` or `sizeof(T)`

---

## 6) Audit Workflow (Repeatable Process)

### Step A — Build & Run Baseline
- Build with max warnings, fix trivial warnings if possible (they hide real bugs).
- Run unit tests and basic runtime flows.

### Step B — Static Analysis Pass
- Run `scan-build`, `clang-tidy`, `cppcheck`.
- Triage results: prioritize memory, integer, taint-like findings.

### Step C — Manual Review by Attack Surface
For each entry point:
1. Trace input → parsing → validation → internal representation
2. Identify all length fields and how they’re used
3. Identify allocations and copies based on those lengths
4. Confirm error handling and cleanup is consistent

### Step D — Sanitizer Runs
- ASan+UBSan for broad coverage
- TSan if concurrent
- Use real inputs + edge-case crafted cases

### Step E — Fuzzing Campaign
- Build fuzz harnesses around parsers/decoders and stateful handlers
- Use sanitizers while fuzzing
- Minimize and deduplicate crashes
- Root-cause each unique crash and assess exploitability

### Step F — Exploitability & Impact Assessment
For each finding:
- Control: can attacker influence size, pointer, index, format?
- Primitive: OOB read/write, UAF, double free, info leak
- Mitigations in build: ASLR, PIE, stack protector, RELRO, CET
- Realistic attack scenario: remote/local, auth required, etc.

---

## 7) Finding Report Template (Use Consistently)
Use this format per issue:

- **Title:** (e.g., Heap OOB write in `parse_header()`)
- **Severity:** Critical/High/Medium/Low
- **Location:** file:line, function
- **Description:** what is wrong
- **Impact:** crash, RCE potential, info leak, privilege escalation, DoS
- **Trigger/Conditions:** specific input/state
- **Root Cause:** missing check, integer overflow, lifetime/ownership error
- **Proof of Concept:** testcase, steps, or fuzz crash details
- **Fix Recommendation:** precise code-level guidance
- **Regression Test:** unit test/fuzz seed to prevent reintroduction

---

## 8) Common C Vulnerability Classes (What to Recognize Quickly)

1. **Stack buffer overflow**
   - local arrays written without bounds checking
2. **Heap buffer overflow**
   - `malloc(len)` but write `len+1`, or miscomputed length
3. **OOB read**
   - information disclosure, can aid exploitation
4. **Use-after-free**
   - stale pointers used after `free`
5. **Double free**
   - may lead to heap corruption
6. **Integer overflow → under-allocation**
   - `n * size` wraps, `malloc` too small, then `memcpy` too large
7. **Format string**
   - `printf(user_input)` or uncontrolled `%n`
8. **Command injection**
   - shell calls with concatenated untrusted strings
9. **Path traversal / TOCTOU**
   - unsafe file opens in writable directories
10. **Race conditions**
   - shared state without proper synchronization

---

## 9) Minimum “Done” Criteria (Exit Conditions)
- All entry points and parsers reviewed with documented trust boundaries
- Static analysis findings triaged; high-impact fixed or justified
- ASan/UBSan test run clean on a representative suite
- Fuzzing performed on key parsers (time-box acceptable), crashes triaged
- Final report delivered with prioritized remediation plan

---

## 10) Practical Tips for High Signal Audits
- Start from **untrusted inputs** and follow the data.
- Treat **length fields** as attacker-controlled unless proven otherwise.
- Pay extra attention to:
  - manual “fast path” optimizations
  - custom allocators
  - “rare error path” code
  - complex state machines and protocol handling
- If you see `assert()` used for validation: remember it may compile out in release builds.

---

## 11) Vulnerability ID Coding Scheme (Finding Identifier)

Assign each discovered vulnerability a unique **Finding ID** using:

**Format:** `<PROJ><NNN>`

- `<PROJ>`: the **first 4 characters** of the project name (use uppercase; if the name is shorter than 4, pad with `X`).
- `<NNN>`: a **3-digit incremental number** starting from `001` (zero-padded).

### Rules
- IDs are assigned **chronologically** as findings are confirmed (not when first suspected).
- IDs are **never reused**. If a finding is invalidated, mark it as **Rejected** but keep the ID.
- If one root cause affects multiple locations, use **one ID** and list all affected sites; if they are distinct root causes, assign separate IDs.

### Examples
- Project name: `openssl` → `OPEN001`, `OPEN002`, `OPEN003`
- Project name: `curl` → `CURL001`, `CURL002`
- Project name: `io` (short) → `IOXX001`, `IOXX002`

### Recommended Usage in Reports
- **Title:** `OPEN007 - Heap OOB write in tls_parse_extensions()`
- **Tracking fields:** `Finding ID`, `Status (Open/Fixed/Rejected)`, `Affected versions/commits`, `Fix commit`, `Regression test reference`
