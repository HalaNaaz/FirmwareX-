# FirmwareX — Firmware Vulnerability Mitigation & Hardening Matrix

> **Document Status:** Authoritative Technical Specification  
> **PRD Deliverable:** Deliverable D — Mitigation Matrix  
> **Compliance Standard:** PRD Appendix A Schema, OWASP IoT Top 10, NIST SP 800-193, CWE Taxonomy

---

## 1. Overview & Defensive Grounding

The FirmwareX Mitigation Matrix bridges automated vulnerability discovery with concrete, evidence-backed firmware hardening recommendations. It maps each finding category identified by the FirmwareX static analysis, ELF binary auditing, and secret scanning engines to specific toolchain flags, Linux kernel configurations, architectural considerations, and verification procedures.

---

## 2. Binary Hardening Mitigation Matrix

| Security Control | Weakness / Vulnerability | Finding Category | CWE Mapping | Toolchain Mitigation Flags | Verification / Validation Command | Residual Risk & Validation Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Non-Executable Stack (NX / DEP)** | Executable stack (`PF_X` flag in `PT_GNU_STACK`). Allows arbitrary shellcode injection into thread/process stacks. | `missing_mitigation` | **CWE-119** (Improper Restriction of Memory Buffer Operations) | GCC / Clang:<br>`-z noexecstack`<br><br>Kernel Config:<br>`CONFIG_STRICT_DEVMEM=y`<br>`CONFIG_CPU_NX=y` | `readelf -l <binary> \| grep -A 1 GNU_STACK`<br><br>*Expected output:*<br>`GNU_STACK ... RW` (no `E` flag) | Binary protection relies on CPU MMU support. On microcontrollers lacking an MPU/MMU, hardware memory isolation is not feasible. |
| **Position-Independent Executable (PIE / ASLR)** | Fixed base load address (`ET_EXEC`). Enables predictable Return-Oriented Programming (ROP) gadgets. | `missing_mitigation` | **CWE-119** / **CWE-1341** | GCC / Clang:<br>`-fPIE -pie`<br><br>Kernel Config:<br>`CONFIG_RANDOMIZE_BASE=y` | `readelf -h <binary> \| grep "Type:"`<br><br>*Expected output:*<br>`Type: DYN (Position-Independent Executable)` | ASLR effectiveness depends on kernel entropy (`/proc/sys/kernel/randomize_va_space = 2`). 32-bit architectures (e.g. MIPS32) offer lower entropy than 64-bit architectures. |
| **Read-Only Relocations (Full RELRO)** | Writable Global Offset Table (`GOT`). Attackers can overwrite function pointers to hijack execution flow. | `missing_mitigation` | **CWE-119** / **CWE-122** | GCC / Clang:<br>`-Wl,-z,relro,-z,now`<br><br>*(Full RELRO)* | `readelf -l <binary> \| grep GNU_RELRO`<br>`readelf -d <binary> \| grep BIND_NOW`<br><br>*Expected:* Both `GNU_RELRO` and `BIND_NOW` flags present | Partial RELRO leaves the GOT writable after startup. Full RELRO binds all symbols at program load time. |
| **Stack Smashing Protection (Canaries)** | Unprotected stack frames. Classic buffer overflows can overwrite return addresses without detection. | `missing_mitigation` | **CWE-121** (Stack-based Buffer Overflow) | GCC / Clang:<br>`-fstack-protector-strong`<br>or `-fstack-protector-all` | `readelf -s <binary> \| grep -E '__stack_chk_fail\|__stack_chk_guard'` | Canaries detect linear buffer overflows that alter the guard value before function return. Non-linear out-of-bounds writes (e.g., array index manipulation) require bounds checking. |
| **FORTIFY_SOURCE** | Unbounded string/memory copy calls (`memcpy`, `strcpy`, `sprintf`). | `missing_mitigation` | **CWE-120** (Classic Buffer Overflow) | GCC / Clang:<br>`-O2 -D_FORTIFY_SOURCE=2`<br>(or `_FORTIFY_SOURCE=3` on glibc 2.34+) | `readelf -s <binary> \| grep -E '__.*_chk'`<br><br>*Expected:* Verified calls to `__memcpy_chk`, `__strcpy_chk`, etc. | Requires compiler optimization level `-O1` or higher. Unbounded structures with dynamic sizes at runtime cannot always be protected at compile time. |
| **Secure Library RPATH / RUNPATH** | Unsafe library search paths (e.g., `.`, relative directories, or writable paths like `/tmp`). | `insecure_configuration` | **CWE-426** (Untrusted Search Path) | GCC / Clang:<br>Avoid `-rpath`. If necessary, use compile-time absolute paths strictly:<br>`-Wl,-rpath,'$ORIGIN/../lib'` | `readelf -d <binary> \| grep -E 'RPATH\|RUNPATH'`<br><br>*Expected:* No relative or writable directory entries. | `$ORIGIN` paths must be protected by read-only root filesystems to prevent binary or library swapping. |

---

## 3. Secrets, Credentials & Cryptographic Mitigations

| Security Control | Weakness / Vulnerability | Finding Category | CWE Mapping | Remediation Guidance | Verification / Validation Command | Residual Risk & Validation Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Embedded Private Keys** | Plaintext RSA, EC, or OpenSSH private keys embedded directly in rootfs images. | `hardcoded_secret` | **CWE-321** / **CWE-798** | Store private device keys in hardware secure elements (TPM 2.0, Secure Enclave, or ATECC608 crypto chips). Provision unique per-device keys during manufacturing. | Run FirmwareX secret scanner:<br>`POST /api/v1/firmware/upload`<br><br>*Expected:* Zero unredacted private keys. | Symmetric key obfuscation in binaries (XOR, AES encryption with hardcoded keys) provides security through obscurity and is easily reversed. |
| **Cloud API & Service Tokens** | Plaintext AWS access keys, JWTs, or third-party service tokens in configuration files. | `hardcoded_secret` | **CWE-798** (Use of Hard-coded Credentials) | Remove static keys. Inject temporary, short-lived scoped credentials at runtime via mutual TLS (mTLS) or OAuth2 device flows. | Search filesystem with entropy scanner:<br>Entropy $> 4.5$ with zero plaintext token hits. | Tokens stored in non-volatile flash or EEPROM must be encrypted with device-unique keys tied to the hardware root of trust. |
| **Legacy Unix Password Hashes** | Shadow databases storing DES (`$1$`), MD5 (`$1$`), or SHA-256 (`$5$`) hashes with low rounds. | `weak_crypto` | **CWE-328** (Reversible / Weak Hash) | Migrate shadow hashes to salted SHA-512 (`$6$`) with at least 50,000 rounds, or Argon2id / yescrypt. Disable default factory passwords. | Inspect `/etc/shadow`:<br>Ensure hashes begin with `$6$` or `$argon2id$`, or root account is locked (`root:*:...` or `root:!:...`). | Weak password policies allow offline dictionary attacks even on modern hashes. Disabling local interactive shell passwords in production firmware is strongly advised. |

---

## 4. Injection & Dangerous Sink Mitigations

| Security Control | Weakness / Vulnerability | Finding Category | CWE Mapping | Remediation Guidance | Verification / Validation Command | Residual Risk & Validation Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Command Injection via Libc Sinks** | Dynamic invocation of `system()` or `popen()` with unvalidated inputs. | `command_injection` | **CWE-78** (OS Command Injection) | Replace `system()` and `popen()` with `execve()` or `posix_spawn()` passing arguments as discrete array vectors. Never invoke `/bin/sh -c` directly with user-controllable input. | Disassemble symbol cross-references to confirm absence of `system` / `popen` in input-handling daemons. | Static reachability leads (`REVIEW_LEAD`) require source code audit to verify whether user data flows into the sink. |
| **Unbounded String Buffer Copying** | Dynamic invocation of `strcpy()`, `sprintf()`, or `gets()`. | `memory_corruption` | **CWE-120** / **CWE-134** | Replace `strcpy()` with `snprintf()` or safe string libraries. Disallow `gets()` completely (`-Werror=implicit-function-declaration`). | Verify that symbol relocation tables link only bounded variants (`snprintf`, `strncpy`, `strlcpy`). | `strncpy` does not guarantee null-termination if the buffer limit is reached; explicit null-termination must be added. |

---

## 5. Architectural Cross-Compilation Matrix

| Architecture | Endianness | Recommended Compiler Target | Hardening Toolchain Preset |
| :--- | :--- | :--- | :--- |
| **MIPS32** | Big-Endian (`mipseb`) | `mips-linux-gnu-gcc` | `-O2 -fPIE -pie -Wl,-z,relro,-z,now -z noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=2` |
| **MIPS32el** | Little-Endian (`mipsel`) | `mipsel-linux-gnu-gcc` | `-O2 -fPIE -pie -Wl,-z,relro,-z,now -z noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=2` |
| **ARMv7-A** | Little-Endian (`armel`/`armhf`) | `arm-linux-gnueabihf-gcc` | `-O2 -fPIE -pie -Wl,-z,relro,-z,now -z noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=2` |
| **AArch64** | Little-Endian (`arm64`) | `aarch64-linux-gnu-gcc` | `-O2 -fPIE -pie -Wl,-z,relro,-z,now -z noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=3 -mbranch-protection=standard` |
| **x86_64** | Little-Endian (`amd64`) | `x86_64-linux-gnu-gcc` | `-O2 -fPIE -pie -Wl,-z,relro,-z,now -z noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fcf-protection=full` |

---

## 6. Audit & Acceptance Checklist

To verify firmware compliance prior to release, security auditors should execute the following automated steps:

- [x] **Step 1:** Ingest firmware archive or filesystem image via FirmwareX (`/api/v1/firmware/upload`).
- [x] **Step 2:** Verify that all extracted ELF executables report `nx.status == "enabled"`.
- [x] **Step 3:** Verify that all extracted ELF executables report `pie.status == "enabled"`.
- [x] **Step 4:** Verify that all extracted ELF executables report `relro.status == "enabled"` (Full RELRO).
- [x] **Step 5:** Review all `hardcoded_secret` findings and ensure zero unredacted credentials exist in `/etc`, `/usr/bin`, or `/var`.
- [x] **Step 6:** Review all `REVIEW_LEAD` candidates linking sources to sinks (`system`, `popen`) and verify input validation.
- [x] **Step 7:** Export the signed JSON compliance report via `/api/v1/firmware/{id}/report`.

