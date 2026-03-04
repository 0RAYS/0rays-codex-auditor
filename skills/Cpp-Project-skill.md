# C++ Project Security Code Audit Skill (Vulnerability Hunting & Bug Finding)

> **Agent instruction:** Before starting this C++ audit, read **`C-Project-skill.md`** and reuse all applicable methodology (threat modeling, workflow, reporting template, grep strategy, sanitizer usage). This C++ skill is an extension: it **adds C++-specific vulnerability classes, review hotspots, and tooling**.

---

## 1) Objective & Scope
**Goal:** Identify security vulnerabilities, reliability bugs, undefined behavior, and design flaws in C++ codebases via manual review, static analysis, and dynamic testing.

**In scope (inherits all from C):**
- Memory safety, integer issues, parsing/input validation
- Concurrency bugs and security boundary violations
- Build configuration risks and unsafe compiler/linker settings

**Additional C++-specific scope:**
- Object lifetime, RAII, exceptions, move semantics
- Templates/generics, type confusion via casts
- Smart pointer misuse and ownership modeling
- ODR (One Definition Rule) / ABI / dynamic linking pitfalls
- Default behaviors (implicit conversions, default copy/move, implicit destructors) that introduce bugs

---

## 2) Tooling & Build Configuration (C++ Focus)

### Compiler Flags (Recommended Additions)
Use the C skill’s warning/hardening baseline, plus:
- `-Wnon-virtual-dtor`
- `-Woverloaded-virtual`
- `-Wold-style-cast`
- `-Wextra-semi`
- `-Wnull-dereference`
- `-Wdouble-promotion`
- `-Wimplicit-fallthrough`
- `-Wzero-as-null-pointer-constant` (mostly for modern C++ codebases)
- Consider: `-Werror` in CI for security-critical components

### Sanitizers & Runtime Checks
Same as C, plus C++-relevant notes:
- **ASan**: catches UAF/OOB that often arise from **incorrect ownership** and **iterator invalidation**.
- **UBSan**: valuable for **vptr issues**, invalid downcasts, misaligned pointers.
- **LSan**: leak detection (especially with exceptions and complex ownership graphs).

### Static Analysis (C++ Strong Picks)
- `clang-tidy` (high value for modern C++ misuse patterns)
- `clang-analyzer` / `scan-build`
- `cppcheck` (some C++ coverage)
- Optional: CodeQL (excellent for C++ codebases if available)

---

## 3) C++-Specific Threat Modeling Notes
Beyond entry points and untrusted inputs (from the C skill), explicitly map:
- **Plugin / shared library boundaries** (ABI mismatches, allocator mismatch, exception propagation across boundaries)
- **Serialization frameworks / reflection** (type confusion, deserialization gadgets)
- **Custom allocators** and **memory resource** usage (`pmr::memory_resource`)

---

## 4) Manual Code Review Checklist (C++ Hotspots)

### 4.1 Default/Implicit Behavior That Causes Vulnerabilities
These are frequent “looks correct” bugs:

#### A) Implicit Copy/Move and the Rule of 3/5/0
Risk:
- Classes managing resources (raw pointers, file handles, mutexes) may get **implicit copy** leading to **double free**, **use-after-free**, or **double close**.

Audit actions:
- Identify types that own resources and ensure:
  - Copy is deleted or properly implemented
  - Move is safe and leaves source in a valid state
- Look for suspicious patterns: raw pointer members, manual `new/delete`, custom destructors.

#### B) Implicit Conversions & Narrowing
Risk:
- Vulnerable logic from implicit numeric conversions, truncation, signedness, `bool` coercions.

Audit actions:
- Track conversions in comparisons and size calculations (`size_t`, `int`, `long`).
- Beware of constructors that are not `explicit`.

#### C) Default `operator==`, ordering, and hashing mismatches
Risk:
- Inconsistent equality/hashing can cause logic bugs, cache poisoning, authz bypass in maps/sets.

Audit actions:
- Check `operator==` vs `std::hash` specialization consistency.
- Ensure stable keys for security decisions.

---

### 4.2 Templates / Generic Code Risks
Templates can magnify subtle bugs across many instantiations.

Common issues:
- **Assumptions about iterator categories** leading to OOB reads/writes.
- **SFINAE/constraints errors** causing unexpected overload selection.
- **Type-dependent behavior**: `sizeof(T)` differences causing allocation mis-sizing.
- **Policy/traits misuse** causing incorrect security checks (e.g., “trusted type” trait accidentally matches attacker-controlled type).

Audit actions:
- Identify templated parsing/serialization utilities and review:
  - Bounds checks independent of `T`
  - No reliance on UB-prone reinterpretation
- Ensure constraints (`concepts`, `enable_if`) enforce intended types.

---

### 4.3 Smart Pointer Misuse (New High-Value Category)
Smart pointers reduce but do not eliminate memory bugs.

#### A) `unique_ptr` pitfalls
- Double ownership via `unique_ptr` constructed from raw pointer already owned elsewhere.
- Custom deleter mismatch (wrong `delete` vs `delete[]` or wrong allocator).

Checks:
- `unique_ptr<T>` should only own pointers created with matching allocation strategy.
- Prefer `make_unique<T>()` / `make_unique<T[]>(n)`.

#### B) `shared_ptr` pitfalls
- **Cycles** → leaks (may become DoS).
- Creating multiple `shared_ptr` from the **same raw pointer** → double free.
- Using `shared_from_this()` without inheriting `enable_shared_from_this` correctly.

Checks:
- Look for `shared_ptr<T>(raw)` and confirm raw is not already managed.
- Use `weak_ptr` to break cycles.
- Ensure lifetime expectations around callbacks and async tasks.

#### C) `weak_ptr` misuse
- Failing to `lock()` and check result before use → UAF-like patterns.

---

### 4.4 Exception Safety & RAII
Security bugs occur when exceptions break invariants.

Common patterns:
- Partially initialized objects used after exception.
- Resource leaks or stale state due to non-RAII management.
- Throwing exceptions across C/ABI boundaries.

Audit actions:
- Identify functions that:
  - allocate/modify state + can throw
  - do manual cleanup rather than RAII
- Verify strong/basic exception guarantees where relevant.
- Ensure destructors do not throw (`noexcept`).

---

### 4.5 Object Lifetime, References, and `string_view` / spans
Modern C++ introduces lifetime hazards:

- Returning `std::string_view` to temporary strings
- Storing `string_view`/`span` that outlives the buffer
- Capturing references in lambdas that outlive scope
- Using iterators after container modification (iterator invalidation)

Audit actions:
- Search for `string_view`, `span`, `c_str()` used beyond lifetime.
- Review async code and callbacks for reference captures (`[&]`).

---

### 4.6 Casting, RTTI, and Type Confusion
High-risk areas:
- `reinterpret_cast`, C-style casts (can hide dangerous conversions)
- `static_cast` downcasts without RTTI checks
- `dynamic_cast` failure not checked (null pointer deref)
- Violations around strict aliasing and object representation

Audit actions:
- Grep for casts and inspect all cross-type conversions.
- Prefer `dynamic_cast` where safe; check results.
- Flag any `reinterpret_cast` on untrusted data paths.

---

### 4.7 Concurrency (C++ Specific Additions)
Beyond C’s concurrency checklist, focus on:
- Data races around `shared_ptr` / ref-counted objects
- Misuse of `std::atomic` (memory order assumptions)
- `double-checked locking` patterns
- Futures/promises with shared state lifetime issues

Audit actions:
- Verify lock coverage for shared state.
- Audit `memory_order_relaxed` usage in security-sensitive flows.

---

### 4.8 STL and Container Misuse
Common bug sources:
- OOB from wrong indexing (`vector.at` vs `operator[]`)
- `std::string` misuse with embedded NULs (binary data)
- `std::vector<bool>` surprises (bitset proxy references)
- `reserve()` vs `resize()` confusion → writing into capacity not size

Audit actions:
- Check all uses of `reserve()` followed by index writes.
- Confirm binary parsing does not treat `std::string` as C-string.

---

## 5) High-Value Searches (C++ Targeted Greps)

```bash
# Smart pointers and ownership
rg -n "shared_ptr<|unique_ptr<|weak_ptr<|make_shared|make_unique|shared_from_this" .

# Views, spans, lifetimes
rg -n "string_view|std::span|gsl::span|c_str\\(\\)|data\\(\\)" .

# Casting
rg -n "reinterpret_cast|dynamic_cast|static_cast|const_cast|\\(.*\\*\\)" .

# Exceptions and noexcept
rg -n "throw |catch\\(|noexcept|~[A-Za-z0-9_]+\\(" .

# Templates and tricky forwarding
rg -n "template<|decltype\\(|std::forward|std::move|enable_if|concept" .
```

---

## 6) Workflow (Reuse C Skill + C++ Enhancements)

1. **Read `C-Project-skill.md`** and apply its workflow end-to-end.
2. **Compile with strict C++ warnings** and enable sanitizers.
3. **Static analysis** with `clang-tidy` configured for the project’s C++ standard.
4. **Manual review by attack surface**, plus targeted review of:
   - resource-owning classes
   - parsers/serializers
   - async/task/callback systems
   - plugin boundaries and shared libraries
5. **Fuzz key parsers** (same approach as C), ensure harness lifetime is correct (avoid harness-only leaks masking issues).

---

## 7) Vulnerability ID Coding Scheme (Same Standard)
Use the same scheme as in the C skill extension:

**Format:** `<PROJ><NNN>`  
- `<PROJ>` = first 4 characters of project name (uppercase; pad with `X` if <4)  
- `<NNN>` = 001, 002, …

Example: `MYPR001`, `MYPR002`

---

## 8) C++-Specific Vulnerability Classes (Quick Recognition List)

1. **Implicit copy → double free / UAF** (Rule of 3/5 violation)
2. **Dangling `string_view` / `span`** (lifetime issues)
3. **Iterator/reference invalidation** after container modification
4. **Multiple `shared_ptr` from same raw pointer** (double delete)
5. **`shared_ptr` cycles** (unbounded memory growth / DoS)
6. **Exception safety bugs** (state corruption, leaks, bypassed checks)
7. **Type confusion via casts** (`reinterpret_cast`, unsafe downcast)
8. **Allocator mismatch across module boundary** (heap corruption)
9. **`reserve()`/`resize()` confusion** causing OOB writes
10. **Template instantiation surprise** (unexpected overload/trait selection)

---

## 9) Reporting Template (Same as C + C++ Fields)
Use the C report template and add when relevant:
- **Lifetime/ownership model:** who owns what; which smart pointer type
- **Exception safety impact:** invariant broken? cleanup skipped?
- **Instantiation scope:** if template bug, list affected instantiations/types

---

## 10) “Done” Criteria (C++ Additions)
In addition to C exit conditions:
- Resource-owning classes audited for Rule of 3/5/0 correctness
- `string_view`/`span` lifetimes reviewed in all public APIs
- Smart pointer ownership patterns validated in async/callback code
- Exception paths tested (including fuzz/crash paths) under sanitizers
