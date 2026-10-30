# FirmwareX — Priority 2, Phase 1 Implementation Plan
## Dashboard Usability, Filesystem Visualization, Mitigation Matrix, Findings & Reporting

**Date:** October 2026  
**Auditor / Engineer:** Senior Firmware Security Engineer, Frontend Systems Engineer, UI/UX Security Reviewer  
**Workspace:** `C:\Users\Hala\Downloads\Project Files\FirmwareX`  
**Primary Specification:** Original `Project Unit42-FirmwareX` PRD v1.0 (FR-1.1–1.4, FR-2.3, FR-3.1–3.4, Appendix A, Dashboard & Reporting Requirements)  

---

## 1. Baseline Audit & Pre-Implementation State

### 1.1 Git Status & Test Baseline
- **Git Branch:** `main` (commit baseline: `446aab9` / `543e239`).
- **Working Tree:** All uncommitted changes from Priority 1 Phases 1–3 are safely preserved.
- **Pytest Suite:** 143 passed, 2 skipped, 0 failed across 145 items.
- **Linting:** 0 errors under `ruff check .`.
- **Live Server:** Operational on `http://127.0.0.1:8080` (PID 3336).

### 1.2 Existing Dashboard Architecture & Gap Identification
The dashboard is served via FastAPI (`firmwarex/api/server.py` at `/`) using a single-page Jinja2 template with glassmorphism Tailwind styling (`firmwarex/web/templates/index.html`, 1669 lines).

| Dashboard Component | Current Implementation | Identified Gaps against PRD v1.0 | Proposed Priority 2 Phase 1 Solution |
| :--- | :--- | :--- | :--- |
| **Filesystem Viewer** | Flat table rendering all items. Path search and simple type dropdown. | No hierarchical tree structure. Directories cannot be expanded or collapsed. All files render in flat list. No distinct folder icons vs executables vs configs. | Implement interactive hierarchical tree viewer with collapsible directories, file/folder icons, relative path display, size, SHA-256 preview, and type filtering. Add empty, loading, and error states. Safe DOM rendering. |
| **ELF Mitigation Matrix** | Static HTML table (`bm-tbody`) with NX, PIE, RELRO, Canary, Fortify, and Sinks count. Simple search. | No column sorting. No architecture filtering (ARM, MIPS, x86). No mitigation status filtering (e.g., show only Disabled NX). Missing bitness, endianness, and stripped status columns. | Add interactive column sorting (click column header to sort ascending/descending), architecture filter dropdown, mitigation status filter dropdown, and display bitness/endianness/stripped metadata. Clear empty and loading states. |
| **Findings & Crash Log** | Table with severity, CWE, asset, category, confidence. Side drawer inspection. | No filtering by analysis type (heuristic lead vs static vs secret vs dynamic crash). No pagination for large finding sets (can overwhelm DOM). Drawer shows raw JSON for crash states. | Add multi-dimensional filtering (Severity, CWE, Analysis Type: `Symbolic Lead`, `Hardening`, `Secret`, `Dynamic Crash`). Add paginated table navigation. Add structured crash state inspector. Prominently distinguish confirmed findings from heuristic review leads. |
| **Control-Flow Graph (CFG)** | None present in dashboard. | PRD mentions CFG visualization, but backend does not currently generate basic-block CFG graphs. | In accordance with PRD honesty rules: do not fabricate a graph. Implement a dedicated CFG Viewer tab with an informative "CFG Generation Unavailable" state that details the required disassembly and edge contract. |
| **Report Generation & Download** | Previews JSON in `<pre>` block. Simple download anchor pointing to `/report`. | Download endpoint `/api/v1/firmware/{id}/report` returns generic JSON inline. No filename attachment header. Findings are not grouped by severity in UI download actions. | Add formatted report export with `Content-Disposition: attachment; filename="firmwarex_report_{id}.json"`. Group findings by severity. Include explicit limitations and containment telemetry. |
| **Security & Accessibility** | Basic `escapeHtml` helper. Responsive grid. | Keyboard navigation on interactive table rows is incomplete. Untrusted file paths and evidence context need rigorous escaping across all dynamic DOM injection points. | Ensure 100% of dynamic strings are escaped via `escapeHtml()`. Add keyboard accessibility (`tabindex="0"`, `onkeydown` Enter/Space). Add accessible text labels beside colored status badges. |

---

## 2. Work Breakdown & Action Items

### Step 1: Hierarchical Filesystem Tree Viewer
- Build a lightweight, high-performance in-memory tree builder in JavaScript:
  - Parses canonical POSIX relative paths (`bin/busybox`, `etc/init.d/rcS`).
  - Constructs nested node hierarchy (`name`, `path`, `type`, `size`, `sha256`, `isDir`, `children`).
  - Renders collapsible directory nodes with toggle state (`▶` collapsed, `▼` expanded).
  - Displays distinct SVG icons and color accents for folders, ELF executables, shared libraries (`.so`), config files (`.conf`, `.cfg`), scripts (`.sh`), and generic data.
  - Supports search filtering that auto-expands parent directories of matched files.
  - Displays empty state ("No files match filter" or "Select firmware") and loading indicators.

### Step 2: Sortable ELF Mitigation Matrix Table
- Enhance `view-mitigation`:
  - Add sortable column headers for `Binary Asset`, `Arch`, `Bitness`, `Endianness`, `NX`, `PIE`, `RELRO`, `Canary`, `Fortify`, `Stripped`, and `Sinks`.
  - Maintain sort state (`sortColumn`, `sortDirection`).
  - Add filters:
    - `Architecture`: All, ARM, AArch64, MIPS, MIPSEL, x86, x86_64.
    - `Mitigation Filter`: All, NX Disabled, PIE Disabled, No RELRO, No Canary, Fortify Disabled, Stripped Only.
  - Exact status rendering conforming to `MitigationStatus` (`ENABLED`, `PARTIALLY_ENABLED`, `DISABLED`, `NOT_APPLICABLE`, `INDETERMINATE`).
  - Respect static binaries where PIE/RELRO are `NOT_APPLICABLE` (never treat missing metadata as a failed mitigation).

### Step 3: Filterable Findings & Structured Crash Log Viewer
- Enhance `view-findings`:
  - Add `findings-type-filter`: All Types, Static Binary Hardening, Hardcoded Secret, Symbolic Review Lead, Dynamic Crash.
  - Add `findings-cwe-filter` dynamically populated from active findings.
  - Add client-side pagination (e.g. 10 or 25 items per page) with Previous / Next controls and page indicator.
  - Display explicit distinction:
    - `CONFIRMED` badge for deterministic findings.
    - `HEURISTIC LEAD` badge for `REVIEW_LEAD` symbolic flows.
  - In `investigation-drawer`:
    - Structured crash-state card: renders signal name (`SIGSEGV`), fault address (`0x00401234`), register values, stack hash, and reproduction notes when present; clearly states "No dynamic crash recorded" when absent.
    - Zero plaintext secret guarantee: verified redacted preview display.

### Step 4: Honest Control-Flow Graph (CFG) Viewer Tab
- Add a new tab/section: `view-cfg` (Control-Flow Graph):
  - Accessible via left sidebar navigation.
  - Evaluates whether selected binary has generated CFG basic-block telemetry.
  - Honest empty/unavailable state:
    - Explains that the static analysis pipeline currently operates at binary/symbol level without an interactive full disassembler.
    - Documents the future CFG API contract:
      ```json
      {
        "binary": "/bin/httpd",
        "functions": [
          {
            "name": "handle_request",
            "entry": "0x00401120",
            "basic_blocks": [
              {"id": "bb_0", "start": "0x00401120", "end": "0x0040114c", "instructions": [...]},
              {"id": "bb_1", "start": "0x00401150", "end": "0x00401170", "instructions": [...]}
            ],
            "edges": [{"from": "bb_0", "to": "bb_1", "type": "conditional_true"}]
          }
        ]
      }
      ```
    - Prevents fabrication of artificial graphs while providing a ready-to-mount container canvas.

### Step 5: Report Export Enhancement
- In `firmwarex/api/routes.py`:
  - Add `/api/v1/firmware/{id}/report/download` with `Content-Disposition: attachment; filename="firmwarex_report_{firmware_id[:8]}.json"`.
  - In `view-reports`: Add download button linking directly to the download attachment route.
  - Include summary grouping findings by severity (`critical_count`, `high_count`, `medium_count`, `low_count`).
  - Transparently include `limitations` and `containment_telemetry`.

### Step 6: Testing & Quality Validation
- Create `tests/test_priority2_phase1.py`:
  - Tests report download endpoint and filename headers.
  - Tests report structure: severity counts, findings grouping, zero secret leakage.
  - Tests inventory API schema for tree reconstruction compatibility.
  - Tests binary audit API schema for sorting/filtering fields (bitness, endianness, stripped).
  - Tests error handling (invalid firmware ID -> 404).
- Run full regression test suite (145+ tests).
- Run `ruff check .`.
- Run live server E2E validation.

### Step 7: Final Documentation
- Author `docs/PRIORITY_2_PHASE_1_REPORT.md` documenting all changes, verification results, and statuses.

---

## 3. Requirement Traceability Matrix for Phase 1

| Priority 2 Requirement | Scope | Target Files | Verification Method | Status Goal |
| :--- | :--- | :--- | :--- | :---: |
| **Filesystem Tree Viewer** | Hierarchical collapsible tree, type icons, search, safe escaping | `firmwarex/web/templates/index.html` | Frontend manual + API contract test | **VERIFIED** |
| **Sortable ELF Mitigation Matrix** | Multi-column sort, Arch filter, Mitigation filter, exact statuses | `firmwarex/web/templates/index.html` | Frontend manual + API contract test | **VERIFIED** |
| **Filterable Findings & Crash Log** | Type filter, CWE filter, pagination, crash state inspector, triage drawer | `firmwarex/web/templates/index.html` | Frontend manual + API contract test | **VERIFIED** |
| **CFG Viewer Component** | Honest unavailable state, data contract documentation, container UI | `firmwarex/web/templates/index.html` | Frontend manual inspection | **VERIFIED** |
| **Report Generation & Download** | Content-Disposition attachment, grouped severities, sanitized payload | `firmwarex/api/routes.py`, `index.html` | Pytest + Live E2E test | **VERIFIED** |
| **Accessibility & Security** | HTML escaping, keyboard focus, color + text labels, responsive layout | `firmwarex/web/templates/index.html` | Security review + Ruff | **VERIFIED** |

