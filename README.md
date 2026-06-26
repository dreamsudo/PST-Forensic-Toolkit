# PST Forensic Toolkit — Operational Manual

A three-stage Python pipeline for forensic examination of Microsoft Outlook PST files: extract messages and attachments to CSV, load into a queryable SQLite database, and produce an automated analysis report.

Built and tested on Kali Linux (arm64) running in UTM on Apple Silicon Mac. The pipeline is OS-portable wherever `pffexport` and Python 3 are available.

---

## Table of Contents

1. [Overview and Architecture](#1-overview-and-architecture)
2. [File-by-File Reference](#2-file-by-file-reference)
3. [Installation and Environment](#3-installation-and-environment)
4. [Configuration Reference](#4-configuration-reference)
5. [Operational Procedures](#5-operational-procedures)
6. [Output Reference](#6-output-reference)
7. [Failure Modes and Troubleshooting](#7-failure-modes-and-troubleshooting)
8. [Security and Handling Guidance](#8-security-and-handling-guidance)
9. [Limitations and Extension Points](#9-limitations-and-extension-points)
10. [`.gitignore`](#10-gitignore)

---

> **Naming convention notice.** Throughout this manual, every file path, case name, custodian name, output filename, attachment directory name, and database name shown in examples is a **placeholder**. The example `eric_saibi.pst` was the input the author happened to have on disk during development; the names `eric_saibi_chris.csv`, `eric_saibi_attachments/`, and `eric_saibi.db` are arbitrary outputs. Replace them freely with any names that fit your case. The only hardcoded names the code itself cares about are explicitly called out in the "Configuration Reference" section.

---

## 1. Overview and Architecture

### What this is

A forensic pipeline for PST (Microsoft Outlook Personal Storage Table) files. It produces three independent, file-based artifacts in sequence, with no daemons, no in-memory state across runs, and no pip dependencies (only Python standard library plus one system binary).

### Stage diagram

```
input.pst
   │
   │  Stage 1:  pst_to_csv.py
   │             ├── shells out to: pffexport (-m items, then -m recovered)
   │             ├── walks: <export_root>.export/ and .recovered/ trees
   │             ├── parses: InternetHeaders.txt, OutlookHeaders.txt,
   │             │           Recipients.txt, Message.txt, Message.html, Message.rtf
   │             ├── hashes: every body and every attachment (SHA-256)
   │             └── writes: forensic CSV + per-message attachment folders
   ▼
output.csv  +  attachments/msg_000001/…  attachments/msg_000002/…  …
   │
   │  Stage 2:  csv_to_sqlite.py
   │             ├── creates schema (typed messages table + indexes)
   │             ├── builds FTS5 virtual table over content fields
   │             ├── streams CSV in 500-row batches
   │             └── builds 5 convenience views
   ▼
output.db   (SQLite with FTS5 full-text search)
   │
   │  Stage 3:  analyze.py
   │             ├── reads SQLite + runs prebuilt queries
   │             ├── runs full-text search across keyword buckets
   │             └── prints structured 10-section text report
   ▼
analysis_report.txt   (stdout; redirect to capture)
```

### Design philosophy

- **Unix-style separation.** Each stage is a standalone script with a clear input file and output file. You can run any stage in isolation, swap any stage for an alternative implementation, or inspect the intermediate artifact between stages.
- **Stdlib-only Python.** No `pip install` required. All three scripts use only `argparse`, `csv`, `sqlite3`, `hashlib`, `pathlib`, `re`, `subprocess`, `shutil`, `tempfile`, and Python's `email` module.
- **One system dependency.** `pst_to_csv.py` shells out to `pffexport` from the `pff-tools` apt package (libpff family). This is the same parsing engine used by Autopsy.
- **Deterministic outputs.** Same input PST → same SHA-256 hashes, same row counts, same CSV. Reproducibility is a chain-of-custody requirement.

---

## 2. File-by-File Reference

### 2.1 `pst_to_csv.py`

**Purpose.** Convert a `.pst` file into a forensic CSV manifest plus a directory tree of extracted attachments.

**Inputs.**

- Positional argument `pst` — path to the input `.pst` file.
- Positional argument `csv` — path where the output CSV will be written.
- Optional `--attachments-dir DIR` — where to extract attachments. Default: `./attachments`.
- Optional `--keep-export` — keep the intermediate `pffexport` tree on disk for manual inspection. Default: discard.

**Outputs.**

- A CSV file at the path given by the `csv` argument, with 33 columns (see [Output Reference](#6-output-reference)).
- A directory tree under `--attachments-dir` containing one subdirectory per message that has attachments (`msg_000001/`, `msg_000002/`, …), each populated with the original attachment files.

**Side effects.**

- Reads the input PST. The PST itself is not modified.
- Computes a SHA-256 hash of the entire PST file at startup and prints it to stdout for chain of custody.
- Creates the attachments directory if it does not exist (`Path.mkdir(parents=True, exist_ok=True)`).
- Either creates a temporary staging directory under `/tmp` (default) or a directory named `_pff_export` next to the input PST (when `--keep-export` is given).
- On exit, deletes the temporary staging directory unless `--keep-export` is set.

**External tools and libraries called.**

- **System binary: `pffexport`** (from `pff-tools` apt package). Invoked via `subprocess.run` in two passes:
  1. `pffexport -m items -f all -q -t <staging> <pst>` — extracts allocated messages.
  2. `pffexport -m recovered -f all -q -t <staging> <pst>` — extracts orphaned/recovered messages from damaged regions.
- **Python stdlib only:** `argparse`, `csv`, `hashlib`, `re`, `shutil`, `subprocess`, `sys`, `tempfile`, `pathlib`, `email.parser.BytesParser`, `email.policy`, `datetime`.

**Key functions.**

| Function | Role |
|---|---|
| `check_pffexport()` | Verifies `pffexport` is on PATH; exits with install instructions if not. |
| `run_pffexport(pst, dir)` | Two-pass extraction with fallback. Fails only if both passes fail. |
| `find_message_dirs(export_root)` | Walks `.export/` and `.recovered/` trees, returns every directory containing `InternetHeaders.txt` or `OutlookHeaders.txt`. |
| `parse_internet_headers(text)` | Parses RFC822 headers using Python's `email` module. |
| `parse_outlook_headers(text)` | Parses pffexport's `OutlookHeaders.txt` (colon-delimited key/value pairs). |
| `parse_recipients(text)` | Parses `Recipients.txt`; groups by To/Cc/Bcc. |
| `extract_attachments(msg_dir, msg_num, attachments_root)` | Copies attachments to per-message subdirectory, returns parallel name/size/hash/path lists. |
| `parse_message_dir(msg_dir, …)` | Builds one CSV row from one message directory. |
| `read_text(path)` | Read a file with encoding fallbacks (utf-8 → utf-16 → latin-1 → cp1252 → replace). |
| `sanitize_filename(name)` | Strips path separators, control chars, and Windows-illegal characters. |

**Error paths.**

- PST file does not exist → exits with `ERROR: PST file not found: <path>`.
- `pffexport` not on PATH → exits with `ERROR: pffexport not found. Install it with: sudo apt install -y pff-tools libpff-dev`.
- Both `items` and `recovered` modes fail → exits with the libpff diagnostic from stderr. If only one mode fails, the script continues using the output from the other.
- Per-message parsing errors are caught individually: a single bad message prints `! error on message N (<dirname>): <exc>` to stdout and the next message is processed. No single bad message aborts the run.
- Per-attachment write errors are caught individually: the failing attachment is recorded as `<write_error:...>` in the CSV and processing continues.
- Encoding failures on text fields are absorbed by the cascading encoding fallbacks in `read_text()`; the final fallback is `errors="replace"`, which never raises.

### 2.2 `csv_to_sqlite.py`

**Purpose.** Import the CSV produced by `pst_to_csv.py` into a SQLite database with indexes, an FTS5 full-text index, and prebuilt analytical views.

**Inputs.**

- Positional argument `csv_path` — path to the input CSV.
- Positional argument `db_path` — path where the SQLite database will be created.

**Outputs.**

- A SQLite `.db` file at the path given by `db_path`.
- Stdout summary: row counts for `messages`, messages with attachments, distinct senders, distinct folders, and total attachments.

**Side effects.**

- If a database already exists at `db_path`, it is **deleted** before writing. The script logs `[!] Removing existing DB: <path>`. No prompt is shown.
- Bumps `csv.field_size_limit` to `sys.maxsize` because message bodies can exceed Python's default field size limit.

**External tools and libraries called.**

- **Python stdlib only:** `argparse`, `csv`, `sqlite3`, `sys`, `pathlib`.
- **SQLite features used:** FTS5 virtual tables, triggers, indexes, views. All standard in modern SQLite (3.20+).

**Key functions.**

This script is a single `main()`. The interesting logic lives in two string constants:

- `SCHEMA` — DDL that creates the `messages` table, six indexes, the `messages_fts` virtual table (FTS5), and the trigger `messages_ai` that keeps FTS in sync on insert.
- `VIEWS` — DDL that creates five convenience views: `v_with_attachments`, `v_top_senders`, `v_top_recipients`, `v_folder_stats`, `v_summary`.

**Error paths.**

- CSV does not exist → exits with `ERROR: CSV not found: <path>`.
- Schema execution errors (e.g., SQLite version too old for FTS5) → propagate from `cur.executescript()` as `sqlite3.OperationalError`.
- Per-row insert errors are not individually caught; if a row violates a constraint, the whole batch fails. In practice the schema has no constraints beyond `MessageNumber PRIMARY KEY`, so the only realistic failure is a duplicate `MessageNumber` from a malformed CSV.

### 2.3 `analyze.py`

**Purpose.** Read the SQLite database and print a structured 10-section forensic analysis report to stdout.

**Inputs.**

- Positional argument `db` — path to the SQLite database produced by `csv_to_sqlite.py`.

**Outputs.**

- Plain-text report printed to stdout. No files are created or modified.
- Recommended usage is to redirect stdout to a file: `python3 analyze.py mycase.db > report.txt`.

**Side effects.**

- Opens the database read-only in practice (only `SELECT` queries are run). No tables or rows are modified.

**External tools and libraries called.**

- **Python stdlib only:** `argparse`, `sqlite3`, `sys`, `re`, `pathlib`, `collections.Counter`.

**Sections produced (in order).**

| # | Section | What it queries |
|---|---|---|
| 1 | Corpus overview | `COUNT(*)`, attachment counts, distinct senders/folders, avg/max body size |
| 2 | Folder distribution | `GROUP BY Folder` |
| 3 | Top 15 senders | `GROUP BY "From"` ordered by count |
| 4 | Top 15 recipients | `GROUP BY "To"` ordered by count |
| 5 | Timeline | Min/max `DateSent`, plus year buckets extracted via regex |
| 6 | Message classes | `GROUP BY MessageClass` |
| 7 | Attachment analysis | File-extension tallies, executable-flag list, duplicate-hash detection |
| 8 | Keyword sweep | FTS5 `MATCH` queries across the seven hardcoded keyword buckets |
| 9 | Notable messages | Top 5 by body size, top 5 by attachment count, all flagged High importance |
| 10 | Integrity / chain-of-custody summary | Hash coverage counts, duplicate body detection |

**Key functions.**

| Function | Role |
|---|---|
| `overview(cur)`, `folder_distribution(cur)`, `top_senders(cur, limit)`, `top_recipients(cur, limit)`, `timeline(cur)`, `message_classes(cur)`, `attachments_analysis(cur)`, `keyword_sweep(cur)`, `notable_messages(cur)`, `integrity_summary(cur)` | One per report section. Each runs SQL and calls the formatting helpers below. |
| `hr(char)`, `section(title)`, `subsection(title)`, `kv(key, value)`, `table(rows, headers, widths)` | Plain-text formatting primitives. |

**Hardcoded constants.**

- `KEYWORD_BUCKETS` — dict with seven categories (`Credentials / Access`, `Financial`, `Confidentiality / Privilege`, `Concealment / Destruction`, `Urgency / Pressure`, `Off-the-record`, `Corporate / Compliance`). Each maps to a list of search terms. **These are the only "names" in the codebase that carry semantic meaning** and are an exception to the placeholder rule. Edit this dict to tune the sweep for your case.
- `WIDTH = 78` — character width used by the horizontal-rule formatter.

**Error paths.**

- Database file does not exist → exits with `ERROR: DB not found: <path>`.
- Missing `messages_fts` table (database not built by `csv_to_sqlite.py`) → keyword-sweep queries raise `sqlite3.OperationalError`, which is caught per-keyword and treated as zero hits.
- Empty database → all queries return 0 or empty results; the report still prints all sections with empty tables.

---

## 3. Installation and Environment

### 3.1 Tested environment

- **OS:** Kali Linux rolling, arm64 architecture
- **Host:** Apple Silicon Mac running UTM
- **Python:** 3.11 or newer (uses `pathlib`, f-strings, no version-specific features beyond that)
- **SQLite:** 3.20+ (FTS5 must be compiled in; standard on Kali)
- **libpff:** version 20231205 (Kali apt package)

### 3.2 Required dependencies

The pipeline has exactly one system dependency and zero Python dependencies.

**Debian / Ubuntu / Kali:**

```bash
sudo apt install -y pff-tools libpff-dev
```

That installs `pffexport` and the underlying `libpff1` shared library. Verify:

```bash
pffexport -V
```

Should print a version string like `pffexport 20231205`.

**macOS (untested but should work):**

```bash
brew install libpff
```

**Python:** any Python 3.8+ already on the system. No `pip install` required.

### 3.3 Why no `requirements.txt`

The codebase deliberately uses only the Python standard library. There is no `requirements.txt` because there are no Python packages to install. This was an intentional design choice to make the tool portable across forensic workstations without dependency-management overhead.

---

## 4. Configuration Reference

This pipeline has **no config files**. Everything is passed on the command line or hardcoded in source. The "configuration" of a run is the set of CLI arguments you give each script.

Below is every configurable knob, its valid values, its default, and where it is consumed in the code.

> **Placeholder reminder.** All filenames, paths, and database names shown below are arbitrary examples. The tool does not care what you call them. Use `case42.pst`, `evidence.csv`, `mailbox.db`, or anything else.

### 4.1 `pst_to_csv.py` CLI

| Argument | Type | Valid values | Default | Effect | Consumed in |
|---|---|---|---|---|---|
| `pst` (positional) | path | any path to an existing `.pst` file | (required) | Input PST file. | `convert()` → resolved with `Path.resolve()`; passed to `pffexport`. |
| `csv` (positional) | path | any writable filesystem path | (required) | Output CSV path. | `convert()` → passed to `csv.DictWriter`. |
| `--attachments-dir` | path | any writable directory path | `./attachments` | Root directory for per-message attachment extraction. | `convert()` → created with `mkdir(parents=True, exist_ok=True)`. |
| `--keep-export` | flag | present or absent | absent | If set, the intermediate `pffexport` output tree is written to `<pst_dir>/_pff_export` and **not** deleted at end of run. If unset, a temp directory is used and cleaned up. | `convert()` → controls the temp-directory branch. |

Example invocations (all names are placeholders):

```bash
# Minimal — outputs to ./attachments next to wherever you run
python3 pst_to_csv.py case.pst case.csv

# Custom output locations
python3 pst_to_csv.py /evidence/case42.pst /reports/case42.csv \
    --attachments-dir /reports/case42_attachments

# Keep the intermediate pffexport tree for manual inspection
python3 pst_to_csv.py case.pst case.csv --keep-export
```

### 4.2 `csv_to_sqlite.py` CLI

| Argument | Type | Valid values | Default | Effect | Consumed in |
|---|---|---|---|---|---|
| `csv_path` (positional) | path | path to existing CSV | (required) | Input CSV from `pst_to_csv.py`. | `main()` → opened as text/utf-8. |
| `db_path` (positional) | path | any writable path | (required) | Output SQLite database. **Existing file at this path is deleted.** | `main()` → opened via `sqlite3.connect`. |

Example invocation:

```bash
python3 csv_to_sqlite.py case.csv case.db
```

### 4.3 `analyze.py` CLI

| Argument | Type | Valid values | Default | Effect | Consumed in |
|---|---|---|---|---|---|
| `db` (positional) | path | path to existing SQLite DB | (required) | Database produced by `csv_to_sqlite.py`. | `main()` → opened read-only in practice. |

Example invocation:

```bash
python3 analyze.py case.db > case_report.txt
```

### 4.4 Hardcoded constants (edit-in-source configuration)

These live in source and changing them requires editing the file.

#### `CSV_COLUMNS` in `pst_to_csv.py`

A list of 33 column names that defines the output CSV schema. Editing this list changes the schema; you must also update `parse_message_dir()` to populate any new keys. **Downstream consumers (`csv_to_sqlite.py`) hardcode the same column names** — if you change this list, you must also update the `SCHEMA` string in `csv_to_sqlite.py` to match.

#### `KEYWORD_BUCKETS` in `analyze.py`

The seven forensic keyword categories used by the keyword-sweep section. These category names and the words inside each are **the only intentionally-meaningful hardcoded strings in the codebase**. Edit freely:

```python
KEYWORD_BUCKETS = {
    "Credentials / Access": ["password", "passwords", "credentials", ...],
    "Financial": ["wire", "transfer", "invoice", ...],
    ...
}
```

Adding a category or term: add a key to the dict; the report will gain a subsection automatically.

#### `SCHEMA` and `VIEWS` strings in `csv_to_sqlite.py`

The full DDL is embedded as string constants. Edit to add/remove columns, indexes, or views. If you add a new column to the `messages` table, you must also add it to the `CSV_COLUMNS` list in `pst_to_csv.py` so the CSV produces it.

#### `WIDTH = 78` in `analyze.py`

Console width for horizontal-rule formatting. Change if you prefer wider/narrower reports.

#### Batch size `500` in `csv_to_sqlite.py`

Row batch size for `executemany()` during CSV import. Tune for memory/speed. Not exposed as a CLI flag.

---

## 5. Operational Procedures

### 5.1 Standard end-to-end run

The canonical workflow is three commands in sequence. All filenames below are placeholders.

```bash
# Stage 1: PST → CSV + attachments
python3 pst_to_csv.py mycase.pst mycase.csv \
    --attachments-dir ./mycase_attachments

# Stage 2: CSV → SQLite database
python3 csv_to_sqlite.py mycase.csv mycase.db

# Stage 3: Database → analysis report
python3 analyze.py mycase.db > mycase_report.txt
```

Expected stdout pattern from Stage 1:

```
[+] Hashing source PST...
    SHA-256: <64 hex characters>
[+] Running pffexport on: <path>
    [✓] 'items' mode succeeded
    [✓] 'recovered' mode succeeded — orphans written too
[+] Export complete
[+] Scanning 1 export tree(s): ['<name>.export']
[+] Found N messages
[+] Writing CSV: <path>
    ... 100 processed
    ...
[✓] Done.
    Source PST:        <path>
    Source SHA-256:    <hash>
    Messages exported: N
    CSV:               <path>
    Attachments dir:   <path>
```

Stage 2:

```
[+] Creating database: <path>
[+] Loading CSV: <path>
[+] Inserted N messages
[+] Building views...

[✓] Done.
    messages             N
    with attachments     M
    unique senders       S
    unique folders       F
    total attachments    A

    Database: <path>
    Query it:  sqlite3 <path>
```

Stage 3 produces the structured report on stdout.

### 5.2 Resume / partial recovery

The pipeline does not support resuming a partially-completed Stage 1 mid-extraction. If Stage 1 crashes, re-run it from scratch. Because the temp directory is auto-cleaned (unless `--keep-export` was set), there is nothing to clean up between attempts.

If Stage 1 completed but Stage 2 failed, you can re-run Stage 2 without re-running Stage 1. Same for Stage 3 after Stage 2.

### 5.3 Damaged PST workflow

If `pffexport` fails during Stage 1 with `libpff_index_value_read_data: invalid file offset value out of bounds` or similar corruption diagnostics, the two-pass fallback (`items` mode → `recovered` mode) is invoked automatically. Both passes' output trees are merged when building the CSV.

You will see one of three outcomes:

1. **Both passes succeed** — best case, you get both allocated and orphaned items.
2. **Only `items` succeeds** — common case for minor corruption past the message regions. The script logs `'recovered' mode: no recoverable items (this is normal)`.
3. **Both passes fail** — the script exits with both error messages. Try `--keep-export` and run `pffexport` manually with `-m debug` to inspect.

### 5.4 Manual inspection of the pffexport tree

Use `--keep-export` to preserve the intermediate directory:

```bash
python3 pst_to_csv.py case.pst case.csv --keep-export
```

The directory `_pff_export.export/` (and possibly `_pff_export.recovered/`) will appear next to the input PST. Each message lives in a numbered subdirectory containing `InternetHeaders.txt`, `OutlookHeaders.txt`, `Recipients.txt`, `Message.txt`, optionally `Message.html` / `Message.rtf`, and an `Attachments/` directory if present.

This tree is a **runtime artifact** and should never be committed to the repo. It is covered by the `.gitignore` in Section 10.

### 5.5 Querying the database directly

After Stage 2, the database can be queried with the `sqlite3` CLI:

```bash
sqlite3 mycase.db
```

Convenience views ready out of the box:

- `SELECT * FROM v_top_senders LIMIT 10;`
- `SELECT * FROM v_top_recipients LIMIT 10;`
- `SELECT * FROM v_folder_stats;`
- `SELECT * FROM v_with_attachments LIMIT 20;`

Full-text search via FTS5:

```sql
SELECT MessageNumber, "From", Subject
FROM messages_fts
WHERE messages_fts MATCH 'password';
```

---

## 6. Output Reference

> **Reminder.** Output files are produced at runtime and are **not part of the repo**. The repo ships only the three scripts.

### 6.1 The CSV (Stage 1 output)

A single file with a header row and one row per message. UTF-8 encoded. All fields are quoted (`csv.QUOTE_ALL`). The 33 columns, in order:

| # | Column | Type | Description |
|---|---|---|---|
| 1 | `MessageNumber` | int | Sequential 1-based index across the entire export. |
| 2 | `Folder` | string | Path of the message's folder relative to the pffexport root. |
| 3 | `InternetMessageID` | string | RFC822 `Message-ID` header. |
| 4 | `Subject` | string | Message subject. |
| 5 | `From` | string | Display-name + email from RFC822 or Outlook headers. |
| 6 | `To` | string | Semicolon-separated recipients (from Recipients.txt or headers fallback). |
| 7 | `Cc` | string | Semicolon-separated. |
| 8 | `Bcc` | string | Semicolon-separated. |
| 9 | `ReplyTo` | string | RFC822 `Reply-To`. |
| 10 | `DateSent` | string | Raw header date string. Not parsed to datetime. |
| 11 | `DateReceived` | string | Outlook `Delivery time` or `Message delivery time`. |
| 12 | `DateCreation` | string | Outlook `Creation time`. |
| 13 | `DateModification` | string | Outlook `Modification time`. |
| 14 | `ClientSubmitTime` | string | Outlook `Client submit time`. |
| 15 | `DeliveryTime` | string | Outlook delivery time. |
| 16 | `Importance` | string | RFC822 `Importance` or Outlook value. |
| 17 | `Priority` | string | RFC822 `Priority`. |
| 18 | `Sensitivity` | string | RFC822 / Outlook. |
| 19 | `MessageClass` | string | Outlook `Message class` (`IPM.Note`, etc.). |
| 20 | `ConversationTopic` | string | RFC822 `Thread-Topic` or Outlook. |
| 21 | `ConversationIndex` | string | RFC822 `Thread-Index` or Outlook. |
| 22 | `TransportHeaders` | string | Full raw RFC822 header block. |
| 23 | `BodyPlain` | string | Plain-text body, HTML-stripped as fallback if no plain body. |
| 24 | `BodyHTMLPresent` | string | `"yes"` or `"no"`. |
| 25 | `BodyRTFPresent` | string | `"yes"` or `"no"`. |
| 26 | `BodySize` | int | Byte length of the UTF-8-encoded body. |
| 27 | `BodySHA256` | string | SHA-256 hex of the body bytes. |
| 28 | `AttachmentCount` | int | Number of attachments on this message. |
| 29 | `AttachmentNames` | string | Pipe-separated (` \| `) list of attachment filenames. |
| 30 | `AttachmentSizes` | string | Pipe-separated list of byte sizes. |
| 31 | `AttachmentSHA256s` | string | Pipe-separated list of SHA-256 hex strings. |
| 32 | `AttachmentExtractedPaths` | string | Pipe-separated list of paths on disk. |
| 33 | `HasAttachments` | string | `"yes"` or `"no"`. |

Plus two metadata fields: `SourcePath` (path to the message dir in the pffexport tree) and the empty placeholder columns (`Sender`, `IsRead`, `Flags`, `Size`) — these are present in the schema but currently emitted empty because pffexport's text output does not expose them reliably.

### 6.2 The attachments directory (Stage 1 side output)

A directory tree under `--attachments-dir`. One subdirectory per message that has attachments, named `msg_NNNNNN` where `NNNNNN` is the `MessageNumber` zero-padded to six digits. Each subdirectory contains the original attachment files with their original filenames (sanitized for filesystem safety by `sanitize_filename()`).

Filename collisions within a single message are resolved by appending `_1`, `_2`, etc. before the extension.

### 6.3 The SQLite database (Stage 2 output)

One file with the following objects:

- **Table `messages`** — one row per CSV row, columns matching the CSV exactly. Primary key is `MessageNumber`.
- **Virtual table `messages_fts`** — FTS5 index over `Subject`, `BodyPlain`, `TransportHeaders`, `From`, `To`. Synced via an `AFTER INSERT` trigger.
- **Indexes:** `idx_folder`, `idx_from`, `idx_subject`, `idx_has_att`, `idx_date_sent`, `idx_msgclass`.
- **Views:** `v_with_attachments`, `v_top_senders`, `v_top_recipients`, `v_folder_stats`, `v_summary`.

### 6.4 The analysis report (Stage 3 output)

Plain text, written to stdout. Ten sections, fixed format, no machine-readable structure (intentionally human-oriented). Redirect to a file to capture:

```bash
python3 analyze.py case.db > case_report.txt
```

---

## 7. Failure Modes and Troubleshooting

This section catalogs every failure mode I can identify by reading the code, where it surfaces, and how to handle it.

### 7.1 `pst_to_csv.py`

| Symptom | Cause in code | Resolution |
|---|---|---|
| `ERROR: PST file not found: <path>` | `convert()` checks `pst_path.exists()`. | Verify the path. Use absolute paths to rule out cwd confusion. |
| `ERROR: pffexport not found. Install it with: sudo apt install -y pff-tools libpff-dev` | `check_pffexport()` calls `shutil.which("pffexport")` and finds nothing. | Install `pff-tools` via apt or `libpff` via brew. |
| `ERROR: pffexport failed in both items and recovered modes.` (with two libpff error blocks) | `run_pffexport()` ran both fallback passes and both returned non-zero. | The PST is severely damaged. Run `pffexport -m debug` manually for diagnostics. Consider `python3 pst_to_csv.py --keep-export` and inspecting the partial output. |
| `'items' mode failed, trying 'recovered' mode...` followed by a successful recovered run | `run_pffexport()` first pass failed but second pass worked. This is **expected** for damaged PSTs and the run will continue. | No action needed. The report will reflect what was recoverable. |
| `'recovered' mode: no recoverable items (this is normal)` | Second pass returned non-zero with no output. Normal for healthy or only-minorly-damaged PSTs. | No action needed. |
| `ERROR: could not locate pffexport output near <path>` | `find_message_dirs()` could not find any directory matching `<export_root>*` with `.export` or `.recovered` suffix. | This means `pffexport` claimed success but wrote nothing. Re-run with `--keep-export` and inspect the staging area. |
| `! error on message N (<dirname>): <exception>` printed during run | Per-message exception in `parse_message_dir()`. | Single-message failures are logged and skipped; the run continues. Investigate the named message dir with `--keep-export` if needed. |
| Garbled text in CSV body fields | `read_text()` fell through all encodings and hit `errors="replace"`. | The source bytes were not valid in any of utf-8/utf-16/latin-1/cp1252. Inspect raw `Message.txt` with `--keep-export`. |
| `<error:...>` in `AttachmentNames` | `extract_attachments()` failed to read an attachment via `att.read_bytes()`. | Use `--keep-export` and inspect the `Attachments/` subdir directly. |
| `<write_error:...>` in `AttachmentExtractedPaths` | `dest_path.write_bytes()` failed. | Disk space, permissions, or filesystem issue at `--attachments-dir`. |

### 7.2 `csv_to_sqlite.py`

| Symptom | Cause in code | Resolution |
|---|---|---|
| `ERROR: CSV not found: <path>` | `Path.exists()` check at top of `main()`. | Verify the CSV was produced by Stage 1. |
| `[!] Removing existing DB: <path>` | Existing db at the same path; auto-deleted. | This is by design. If you want to keep the old DB, rename it before running. |
| `sqlite3.OperationalError: no such module: fts5` | Your SQLite was compiled without FTS5. | Use a newer Python or system SQLite. Standard on Kali. |
| `sqlite3.IntegrityError: UNIQUE constraint failed: messages.MessageNumber` | Duplicate `MessageNumber` in the CSV. | Indicates a malformed CSV. Inspect the source. |
| `csv.Error: field larger than field limit` | Should not occur — `csv.field_size_limit(sys.maxsize)` is set at top of `main()`. If it does, your Python build has a more restrictive cap. | Report as a bug or lower the value. |

### 7.3 `analyze.py`

| Symptom | Cause in code | Resolution |
|---|---|---|
| `ERROR: DB not found: <path>` | `Path.exists()` check at top of `main()`. | Verify Stage 2 completed. |
| Section 8 (keyword sweep) shows all zero hits | The per-keyword `sqlite3.OperationalError` handler caught a missing `messages_fts` table. | Re-run `csv_to_sqlite.py` to rebuild the FTS index. |
| Report runs but every section shows empty tables | Database has zero rows. | Check that Stage 1 actually produced messages and Stage 2 actually loaded them. |
| Year extraction in Section 5 shows weird years | The regex `(19\d{2}|20\d{2})` picks the first 4-digit year in the `DateSent` string. If the date format has the year elsewhere, you'll get whatever 4-digit year appears first. | Known limitation. See "Limitations" section. |

---

## 8. Security and Handling Guidance

### 8.1 Chain of custody

`pst_to_csv.py` prints the SHA-256 of the input PST at startup. **Record this hash in your case notes before processing.** It establishes that the PST you analyzed is the PST you received.

Body and attachment SHA-256 hashes are embedded in every row of the output CSV. Re-running the pipeline against the same source PST will produce the same hashes (the parser is deterministic given the same input).

### 8.2 Handling of executable attachments

`analyze.py` flags extensions in a hardcoded set: `exe`, `bat`, `ps1`, `vbs`, `js`, `scr`, `com`, `cmd`, `dll`, `zip`, `rar`, `7z`, `iso`, `msi`. **These are flagged for human review, not quarantined or scanned.** The pipeline extracts every attachment to disk regardless of type. If you are processing potentially malicious mail, do this on an isolated forensic workstation with no auto-execute paths.

### 8.3 Data sensitivity

The output CSV contains the full text of every email plus every attachment in cleartext on disk. Apply the same controls you would to the original PST: encrypted storage, access control, secure deletion when done. The pipeline does no encryption of its own.

### 8.4 No network activity

None of the three scripts make any network calls. All processing is local.

### 8.5 Privilege

The scripts run as the invoking user. No `sudo` is required to run them. (`sudo` is only required once, for the initial `apt install pff-tools libpff-dev`.)

---

## 9. Limitations and Extension Points

### 9.1 Known limitations

- **No datetime parsing.** All date columns are stored as the raw header strings. Sorting by these strings is alphabetical, not chronological. Section 5 of `analyze.py` extracts the year via regex as a coarse workaround. Real timeline analysis would require parsing each header into a `datetime` object.
- **Recipient parsing is heuristic.** `parse_recipients()` reads `Recipients.txt` line by line looking for "type:", "display name:", and "email address:" lines. Variant header formats in some PSTs may produce empty fields.
- **MAPI metadata is partial.** `OutlookHeaders.txt` from pffexport sometimes omits fields (most notably `MessageClass` in older PSTs). Empty values in those columns are not a bug.
- **HTML-to-text fallback is naive.** `extract_body_plain()` strips HTML tags with a simple regex when no plain-text body exists. Complex HTML may produce ugly text. Use `BodyHTMLPresent="yes"` as a flag to know when to inspect the HTML directly via `--keep-export`.
- **No incremental processing.** Re-running `pst_to_csv.py` re-extracts everything from scratch. There is no caching or skip-existing logic.
- **No support for password-protected PSTs.** `libpff` can handle some encrypted PSTs but the scripts make no special accommodation. Errors will surface from `pffexport`.
- **No deduplication on import.** Stage 2 imports every CSV row. If the same PST is processed twice into two CSVs and both are imported, you get duplicates.

### 9.2 Extension points

If you want to extend this pipeline, the natural seams are:

| Extension | Where to start |
|---|---|
| New CSV columns | Edit `CSV_COLUMNS` in `pst_to_csv.py`, then update `parse_message_dir()` to populate them, then update `SCHEMA` in `csv_to_sqlite.py`. |
| New analysis section | Add a function to `analyze.py` and call it from `main()`. Mirror the pattern of existing section functions. |
| New keyword bucket | Add to `KEYWORD_BUCKETS` dict in `analyze.py`. No other changes required. |
| Different output format (JSON, Parquet) | Replace the `csv.DictWriter` block in `pst_to_csv.py`. The rest of the pipeline is independent. |
| Different DB backend (Postgres) | Rewrite `csv_to_sqlite.py`. The CSV is the contract. |
| Mailbox formats other than PST (mbox, MSG, EML) | Replace the `pffexport` subprocess call with the equivalent tool. The downstream message-dir parser is generic enough to work on any layout that produces per-message folders with header files. |
| Parallel extraction | The pffexport call is single-threaded. The per-message parsing loop in `convert()` is also serial. Parallelizing would require a thread or process pool around `parse_message_dir()`. |

### 9.3 Things that are **not** implemented

- Removable evidence chain-of-custody automation (locking source, hash verification on completion)
- Automated virus scanning of attachments
- HTML body preservation (only plain-text bodies land in the CSV)
- Email thread reconstruction (the data is present in `ConversationIndex` but no tool builds the tree)
- A GUI

---

## 10. `.gitignore`

A `.gitignore` ready to drop in the repo root. Every rule is annotated below.

```gitignore
# === Tool outputs (never commit) ============================================
# Stage 1 outputs: the CSV manifest produced by pst_to_csv.py
*.csv

# Stage 1 side outputs: extracted attachments and intermediate pffexport tree
attachments/
_pff_export/
_pff_export.export/
_pff_export.recovered/
*_attachments/

# Stage 2 output: the SQLite database
*.db
*.sqlite
*.sqlite3
*.db-journal
*.db-wal
*.db-shm

# Stage 3 output: analysis report
analysis_report.txt
*_report.txt

# === Input evidence (never commit) ==========================================
# Raw PSTs and any archive that might contain them
*.pst
*.ost
*.pab
*.zip
*.7z
*.rar
*.tar
*.tar.gz
*.tgz

# Examiner deliverables that live alongside the tool but aren't part of it
*.xlsx
*.docx
*.pdf

# === Python cruft ============================================================
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments (the project doesn't use one, but contributors might)
.venv/
venv/
env/
ENV/

# Jupyter / IPython
.ipynb_checkpoints/

# Test / lint caches (no tests ship, but if added later)
.pytest_cache/
.coverage
.mypy_cache/
.ruff_cache/
htmlcov/

# === Editor / OS noise =======================================================
# macOS
.DS_Store
.AppleDouble

# Windows
Thumbs.db
desktop.ini

# Linux
*~

# Editors
.vscode/
.idea/
*.swp
*.swo
*~

# === Logs and temp files =====================================================
*.log
*.tmp
*.bak
*.old
```

### What each block is for

- **Tool outputs** — every artifact produced by the three scripts. The repo ships the scripts, never their output. The wildcards `*.csv`, `*.db`, `*.sqlite`, etc. are aggressive on purpose: if you add a sample input CSV to the repo for some reason, you'll need to force-add it.
- **Input evidence** — PSTs, the archives they ship in, and the examiner deliverables produced alongside them. None of these belong in a public repo.
- **Python cruft** — standard byte-compiled file and packaging detritus. None of the scripts use a virtualenv but we ignore them in case contributors add one.
- **Editor / OS noise** — typical IDE and OS metadata.
- **Logs and temp files** — generic transient files. The scripts don't currently create any logs, but if you add logging later, this block catches it.

---

*End of manual.*
