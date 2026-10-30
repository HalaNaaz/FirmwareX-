# FirmwareX — Priority 1, Phase 1 Implementation Plan
## Core Static Analysis & Firmware Extraction Audit & Hardening

**Date:** October 2026  
**Auditor / Engineer:** Senior Firmware Security Engineer & Python Systems Specialist  
**Specification:** Original `Project Unit42-FirmwareX` PRD v1.0 (FR-1.1 through FR-1.4, Week 1 Exit Criteria)  
**Workspace:** `C:\Users\Hala\Downloads\Project Files\FirmwareX`

---

## 1. Executive Summary & Audit Baseline

FirmwareX is an automated IoT/embedded firmware attack surface and vulnerability analysis engine.
Under Priority 1 — Phase 1, our mandate is strictly focused on **Static Analysis & Firmware Extraction**, specifically PRD requirements:
- **FR-1.1:** Firmware Image Ingestion & Multi-Format Parsing
- **FR-1.2:** Filesystem Reconstruction & File Inventory
- **FR-1.3:** Embedded Binary Discovery & Architecture Identification
- **FR-1.4:** Static ELF Hardening Audit (Mitigation Matrix)
- **Week 1 Exit Criteria:** Extraction success rate benchmark, full test suite pass, and zero regressions on the live server.

### Audit Findings

1. **FR-1.1 (Multi-Format Extraction):**
   - **Current State:** Extractors exist for CramFS (`cramfs_extractor.py`), TRX (`trx_extractor.py`), uImage (`uimage_extractor.py`), JFFS2/UBIFS (`jffs2_ubifs_extractor.py`), SquashFS (`squashfs_extractor.py`), and standard archives (`archive_extractor.py`: ZIP, TAR, GZ, BZ2, XZ).
   - **Gaps Identified:**
     - Missing dedicated extractor for `cpio` (standard Linux initramfs / initrd format widely used across embedded routers and IoT devices). CPIO magic `070701` / `070702` (new ASCII) and `070707` (binary) need a streaming, path-traversal-safe extractor.
     - Extractor registry lacks direct CPIO dispatch.
   - **Action:** Create `CpioExtractor` in `firmwarex/core/extractors/cpio_extractor.py` and register it in `ExtractorRegistry` and `raw_detector.py`.

2. **FR-1.2 (Filesystem Reconstruction & Inventory):**
   - **Current State:** `firmwarex/core/unpacker.py` extracts archives and produces a file inventory with path, size, and SHA-256.
   - **Gaps Identified:**
     - In some code paths, file hashing or reading loaded data into memory or read small files at once. Hashing large unpacked files must strictly stream chunks (64 KB) to adhere to PRD low-memory bounds and avoid host OOM.
     - Ensure inventory metadata strictly reports normalized relative paths (no host path leaks), symlink targets, file types (regular file, directory, symlink, block/char device indicator), and sizes.
   - **Action:** Enforce buffered streaming SHA-256 calculation across `unpacker.py` and ensure file inventory entries are clean and deterministic.

3. **FR-1.3 (ELF Discovery & Architecture Metadata):**
   - **Current State:** `firmwarex/core/elf_auditor.py` parses ELFs with `pyelftools`.
   - **Gaps Identified:**
     - Explicit detection of `stripped` vs `unstripped` binaries (`.symtab` presence and symbol count) was not fully exposed in the top-level metadata dictionary.
     - Non-crashing error handling on corrupted/truncated ELFs must return safe fallback records with `status="malformed"` rather than raising unhandled exceptions.
   - **Action:** Add `is_stripped`, `num_symbols`, `interpreter`, and robust exception isolation to `ElfAuditor.audit_binary()`.

4. **FR-1.4 (Static ELF Hardening Audit):**
   - **Current State:** Checks for NX, PIE, RELRO (none, partial, full), Stack Canaries, FORTIFY_SOURCE, RPATH/RUNPATH, and insecure sinks (`system`, `strcpy`, etc.).
   - **Gaps Identified:**
     - Ensure explicit distinction between `enabled`, `disabled`, and `unknown` / `not_applicable` (e.g. static binaries where RELRO or dynamic tags are not applicable, or corrupted binaries where section headers are stripped/missing).
   - **Action:** Audit hardening evaluator rules to ensure no misleading false positives/negatives when dealing with static binaries or stripped symbol tables.

---

## 2. Implementation Work Breakdown

| Step | Component | Target Files | Key Changes |
| :--- | :--- | :--- | :--- |
| **Step 1** | CPIO Extractor (FR-1.1) | `firmwarex/core/extractors/cpio_extractor.py`<br>`firmwarex/core/extractors/registry.py`<br>`firmwarex/core/raw_detector.py` | Implement pure-Python streaming `CpioExtractor` handling ASCII (`070701`/`070702`) and binary CPIO archives with zip-slip safety, size quotas, and file limits. Register in extractor pipeline. |
| **Step 2** | Streaming File Inventory (FR-1.2) | `firmwarex/core/unpacker.py` | Use 64KB chunk buffered hashing (`hashlib.sha256`) for inventory generation. Ensure symlink safety, relative path normalization, zero host path leaks. |
| **Step 3** | ELF Metadata & Hardening Refinement (FR-1.3, FR-1.4) | `firmwarex/core/elf_auditor.py` | Expose `is_stripped`, `symbol_count`, `has_debug_info`, `interpreter`. Differentiate `not_applicable` for static binaries. Gracefully handle malformed headers with `status: malformed`. |
| **Step 4** | Synthetic Test Fixtures & Unit Tests | `tests/fixtures_extractors.py`<br>`tests/test_priority1_phase1.py` | Add synthetic CPIO generator, stripped/unstripped ELF fixtures, malformed ELF fixtures, corrupted headers, and large file streaming tests. |
| **Step 5** | Extraction Benchmark & Test Suite | Test suite & local scripts | Run extraction benchmark across CramFS, TRX, uImage, JFFS2, SquashFS, CPIO, TAR, ZIP fixtures. Confirm >90% extraction rate. Run full pytest suite and Ruff linter. |
| **Step 6** | Priority 1 Phase 1 Report | `docs/PRIORITY_1_PHASE_1_REPORT.md` | Author evidence-backed release report with requirement statuses and benchmark results. |

---

## 3. Constraints & Safe Execution Checklist

- [x] No code rebuild from scratch; maintain existing FastAPI routes, models, database schemas, and normalized finding formats.
- [x] Do not execute untrusted binaries on Windows host.
- [x] Maintain operational background server on `127.0.0.1:8080`.
- [x] Do NOT commit or push to GitHub (per explicit instruction).

