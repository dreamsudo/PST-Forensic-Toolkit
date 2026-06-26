#!/usr/bin/env python3
"""
analyze.py — Automated forensic analysis of the Eric Saibi email corpus
========================================================================
Reads eric_saibi.db (built by csv_to_sqlite.py) and prints a structured
report covering volume, senders/recipients, timeline, attachments,
keyword sweeps, and integrity stats.

Usage:
    python3 analyze.py eric_saibi.db
    python3 analyze.py eric_saibi.db > analysis_report.txt
"""

import argparse
import sqlite3
import sys
from collections import Counter
from pathlib import Path


# Keywords worth sweeping for in any e-discovery investigation
KEYWORD_BUCKETS = {
    "Credentials / Access": [
        "password", "passwords", "credentials", "login", "username", "passcode"
    ],
    "Financial": [
        "wire", "transfer", "invoice", "payment", "account", "routing", "swift"
    ],
    "Confidentiality / Privilege": [
        "confidential", "privileged", "attorney", "lawyer", "legal", "counsel", "NDA"
    ],
    "Concealment / Destruction": [
        "delete", "destroy", "shred", "burn", "purge", "scrub", "erase"
    ],
    "Urgency / Pressure": [
        "urgent", "asap", "immediately", "emergency", "deadline"
    ],
    "Off-the-record": [
        "off the record", "do not forward", "between us", "keep this quiet", "private"
    ],
    "Corporate / Compliance": [
        "audit", "compliance", "SEC", "regulator", "subpoena", "investigation"
    ],
}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
WIDTH = 78

def hr(char="="):
    print(char * WIDTH)

def section(title):
    print()
    hr("=")
    print(f"  {title}")
    hr("=")

def subsection(title):
    print()
    print(f"--- {title} ---")

def kv(key, value, key_width=30):
    print(f"  {key:<{key_width}} {value}")

def table(rows, headers, widths=None):
    if not rows:
        print("  (no data)")
        return
    if widths is None:
        widths = []
        for i, h in enumerate(headers):
            longest = max([len(str(h))] + [len(str(r[i])) for r in rows])
            widths.append(min(longest, 50))
    line = "  " + "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
    print(line)
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        cells = []
        for v, w in zip(r, widths):
            s = str(v) if v is not None else ""
            if len(s) > w:
                s = s[: w - 1] + "\u2026"
            cells.append(f"{s:<{w}}")
        print("  " + "  ".join(cells))


# ---------------------------------------------------------------------------
# Analysis sections
# ---------------------------------------------------------------------------
def overview(cur):
    section("1. CORPUS OVERVIEW")

    total      = cur.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    with_att   = cur.execute("SELECT COUNT(*) FROM messages WHERE HasAttachments='yes'").fetchone()[0]
    senders    = cur.execute("SELECT COUNT(DISTINCT \"From\") FROM messages WHERE \"From\"!=''").fetchone()[0]
    folders    = cur.execute("SELECT COUNT(DISTINCT Folder) FROM messages").fetchone()[0]
    total_att  = cur.execute("SELECT SUM(AttachmentCount) FROM messages").fetchone()[0] or 0
    avg_body   = cur.execute("SELECT AVG(BodySize) FROM messages").fetchone()[0] or 0
    max_body   = cur.execute("SELECT MAX(BodySize) FROM messages").fetchone()[0] or 0

    kv("Total messages",                f"{total:,}")
    kv("Messages with attachments",     f"{with_att:,}  ({with_att/total*100:.1f}%)")
    kv("Total attachments extracted",   f"{total_att:,}")
    kv("Unique senders",                f"{senders:,}")
    kv("Folders represented",           f"{folders}")
    kv("Average body size",             f"{avg_body:,.0f} bytes")
    kv("Largest body size",             f"{max_body:,} bytes")


def folder_distribution(cur):
    section("2. FOLDER DISTRIBUTION")
    rows = cur.execute("""
        SELECT Folder, COUNT(*) AS msgs, SUM(AttachmentCount) AS atts
        FROM messages
        GROUP BY Folder
        ORDER BY msgs DESC
    """).fetchall()
    table(rows, ["Folder", "Messages", "Attachments"], widths=[50, 10, 12])


def top_senders(cur, limit=15):
    section(f"3. TOP {limit} SENDERS")
    rows = cur.execute("""
        SELECT "From", COUNT(*) AS msgs
        FROM messages
        WHERE "From" != ''
        GROUP BY "From"
        ORDER BY msgs DESC
        LIMIT ?
    """, (limit,)).fetchall()
    table(rows, ["From", "Messages"], widths=[60, 10])


def top_recipients(cur, limit=15):
    section(f"4. TOP {limit} RECIPIENTS (To: field)")
    rows = cur.execute("""
        SELECT "To", COUNT(*) AS msgs
        FROM messages
        WHERE "To" != ''
        GROUP BY "To"
        ORDER BY msgs DESC
        LIMIT ?
    """, (limit,)).fetchall()
    table(rows, ["To", "Messages"], widths=[60, 10])


def timeline(cur):
    section("5. TIMELINE")
    earliest = cur.execute("""
        SELECT DateSent FROM messages
        WHERE DateSent != ''
        ORDER BY DateSent ASC LIMIT 1
    """).fetchone()
    latest = cur.execute("""
        SELECT DateSent FROM messages
        WHERE DateSent != ''
        ORDER BY DateSent DESC LIMIT 1
    """).fetchone()

    kv("Earliest dated message", earliest[0] if earliest else "n/a")
    kv("Latest dated message",   latest[0] if latest else "n/a")

    # Year breakdown — DateSent format varies, extract a 4-digit year from anywhere in it
    subsection("Messages per year (approximate)")
    rows = cur.execute("SELECT DateSent FROM messages WHERE DateSent != ''").fetchall()
    years = Counter()
    import re
    for (ds,) in rows:
        m = re.search(r"(19\d{2}|20\d{2})", ds)
        if m:
            years[m.group(1)] += 1
    year_rows = sorted(years.items())
    table(year_rows, ["Year", "Messages"], widths=[10, 10])


def message_classes(cur):
    section("6. MESSAGE CLASSES (Outlook MAPI item types)")
    rows = cur.execute("""
        SELECT MessageClass, COUNT(*) AS cnt
        FROM messages
        GROUP BY MessageClass
        ORDER BY cnt DESC
    """).fetchall()
    table(rows, ["MessageClass", "Count"], widths=[45, 10])

    encrypted = cur.execute("""
        SELECT COUNT(*) FROM messages
        WHERE MessageClass LIKE '%SMIME%' OR MessageClass LIKE '%encrypted%' OR MessageClass LIKE '%signed%'
    """).fetchone()[0]
    if encrypted:
        subsection("Forensic note")
        print(f"  {encrypted} message(s) appear to be encrypted/signed (S/MIME).")
        print("  These warrant manual review — content may not be in plain-text body.")


def attachments_analysis(cur):
    section("7. ATTACHMENT ANALYSIS")

    # File extension breakdown
    rows = cur.execute("""
        SELECT AttachmentNames FROM messages
        WHERE HasAttachments='yes' AND AttachmentNames != ''
    """).fetchall()

    ext_counter = Counter()
    total_files = 0
    for (names,) in rows:
        for name in names.split(" | "):
            name = name.strip()
            if not name:
                continue
            total_files += 1
            if "." in name:
                ext = name.rsplit(".", 1)[-1].lower()
                ext_counter[ext] += 1
            else:
                ext_counter["(no extension)"] += 1

    subsection(f"File-type breakdown ({total_files} attachments)")
    top_exts = ext_counter.most_common(20)
    table(top_exts, ["Extension", "Count"], widths=[20, 10])

    # Forensic-flag extensions
    flag_exts = {"exe", "bat", "ps1", "vbs", "js", "scr", "com", "cmd", "dll",
                 "zip", "rar", "7z", "iso", "msi"}
    suspicious = [(e, c) for e, c in ext_counter.items() if e in flag_exts]
    if suspicious:
        subsection("\u26a0  Potentially executable or archive attachments (review manually)")
        table(suspicious, ["Extension", "Count"], widths=[20, 10])
    else:
        subsection("No executable-type attachments detected")

    # Duplicate attachments (same SHA-256 appearing in multiple messages)
    subsection("Duplicate attachments (same SHA-256 in multiple messages)")
    dup_rows = cur.execute("""
        SELECT AttachmentSHA256s FROM messages
        WHERE AttachmentSHA256s != ''
    """).fetchall()
    hash_counter = Counter()
    for (h_blob,) in dup_rows:
        for h in h_blob.split(" | "):
            h = h.strip()
            if h and len(h) == 64:
                hash_counter[h] += 1
    dups = [(h, c) for h, c in hash_counter.items() if c > 1]
    dups.sort(key=lambda x: -x[1])
    if dups:
        kv("Unique attachment hashes", f"{len(hash_counter):,}")
        kv("Hashes seen >1 time",       f"{len(dups):,}")
        kv("Most duplicated hash",      f"{dups[0][0][:16]}\u2026  (appears {dups[0][1]} times)")
    else:
        print("  No duplicate attachments by hash.")


def keyword_sweep(cur):
    section("8. KEYWORD SWEEP (full-text search)")
    print("  Hits across Subject + Body + Headers + From + To")
    print()

    for bucket, words in KEYWORD_BUCKETS.items():
        subsection(bucket)
        rows = []
        for w in words:
            try:
                cnt = cur.execute(
                    "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH ?",
                    (w,),
                ).fetchone()[0]
            except sqlite3.OperationalError:
                cnt = 0
            rows.append((w, cnt))
        rows.sort(key=lambda x: -x[1])
        table(rows, ["Keyword", "Messages"], widths=[30, 10])


def notable_messages(cur):
    section("9. NOTABLE MESSAGES")

    # Largest body
    subsection("5 largest message bodies")
    rows = cur.execute("""
        SELECT MessageNumber, "From", Subject, BodySize
        FROM messages
        ORDER BY BodySize DESC
        LIMIT 5
    """).fetchall()
    table(rows, ["#", "From", "Subject", "BodySize"], widths=[5, 35, 30, 10])

    # Most attachments on a single message
    subsection("5 messages with the most attachments")
    rows = cur.execute("""
        SELECT MessageNumber, "From", Subject, AttachmentCount
        FROM messages
        WHERE AttachmentCount > 0
        ORDER BY AttachmentCount DESC
        LIMIT 5
    """).fetchall()
    table(rows, ["#", "From", "Subject", "Attachments"], widths=[5, 35, 30, 12])

    # High-importance
    subsection("Messages flagged High importance")
    rows = cur.execute("""
        SELECT MessageNumber, "From", Subject
        FROM messages
        WHERE Importance != '' AND Importance != 'Normal' AND Importance != '1'
        LIMIT 10
    """).fetchall()
    if rows:
        table(rows, ["#", "From", "Subject"], widths=[5, 35, 40])
    else:
        print("  None found.")


def integrity_summary(cur):
    section("10. INTEGRITY / CHAIN-OF-CUSTODY SUMMARY")

    have_body_hash = cur.execute(
        "SELECT COUNT(*) FROM messages WHERE BodySHA256 != ''"
    ).fetchone()[0]
    have_att_hash = cur.execute(
        "SELECT COUNT(*) FROM messages WHERE AttachmentSHA256s != ''"
    ).fetchone()[0]
    total = cur.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    kv("Messages with body SHA-256",       f"{have_body_hash:,} / {total:,}")
    kv("Messages with attachment SHA-256", f"{have_att_hash:,}")

    # Duplicate body hashes (could indicate repeated content / mass-mail)
    dup_bodies = cur.execute("""
        SELECT BodySHA256, COUNT(*) AS occurrences
        FROM messages
        WHERE BodySHA256 != ''
        GROUP BY BodySHA256
        HAVING occurrences > 1
        ORDER BY occurrences DESC
        LIMIT 5
    """).fetchall()
    subsection("Top duplicate message bodies (possible mass-sends / forwards)")
    if dup_bodies:
        table(
            [(h[:16] + "\u2026", c) for h, c in dup_bodies],
            ["Body SHA-256 (prefix)", "Times seen"],
            widths=[25, 12],
        )
    else:
        print("  No duplicate bodies detected.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Forensic analysis report.")
    parser.add_argument("db", help="Path to SQLite DB built by csv_to_sqlite.py")
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    if not db_path.exists():
        sys.exit(f"ERROR: DB not found: {db_path}")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Header
    hr("#")
    print("  EMAIL E-DISCOVERY — AUTOMATED FORENSIC ANALYSIS REPORT")
    hr("#")
    kv("Source database", db_path)
    kv("Generated by",    "analyze.py")

    overview(cur)
    folder_distribution(cur)
    top_senders(cur)
    top_recipients(cur)
    timeline(cur)
    message_classes(cur)
    attachments_analysis(cur)
    keyword_sweep(cur)
    notable_messages(cur)
    integrity_summary(cur)

    print()
    hr("#")
    print("  END OF REPORT")
    hr("#")
    print()

    conn.close()


if __name__ == "__main__":
    main()
