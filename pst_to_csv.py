#!/usr/bin/env python3
"""
pst_to_csv.py — Forensic PST-to-CSV converter (Kali arm64 edition)
==================================================================
Custom-built replacement for Aid4Mail Converter. Runs natively on
Kali Linux arm64 (Apple Silicon Mac → UTM → Kali).

Architecture-agnostic approach: instead of relying on the pypff
Python bindings (which can be flaky on arm64), this script shells
out to `pffexport` from the `pff-tools` apt package — the same
libpff engine, exposed as a CLI. Then it walks the exported tree
and assembles a forensic-grade CSV.

Pipeline:
    eric_saibi.pst  →  pffexport  →  ./_pff_export/  →  pst_to_csv.py  →  eric_saibi.csv
                                                                       →  ./attachments/

Usage:
    python3 pst_to_csv.py <input.pst> <output.csv> [--attachments-dir DIR] [--keep-export]

Example:
    python3 pst_to_csv.py eric_saibi.pst eric_saibi_chris.csv \\
        --attachments-dir ./eric_saibi_attachments
"""

import argparse
import csv
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path


# ---------------------------------------------------------------------------
# CSV columns — full forensic dump
# ---------------------------------------------------------------------------
CSV_COLUMNS = [
    "MessageNumber",
    "Folder",
    "InternetMessageID",
    "Subject",
    "From",
    "To",
    "Cc",
    "Bcc",
    "ReplyTo",
    "DateSent",
    "DateReceived",
    "DateCreation",
    "DateModification",
    "ClientSubmitTime",
    "DeliveryTime",
    "Importance",
    "Priority",
    "Sensitivity",
    "MessageClass",
    "ConversationTopic",
    "ConversationIndex",
    "TransportHeaders",
    "BodyPlain",
    "BodyHTMLPresent",
    "BodyRTFPresent",
    "BodySize",
    "BodySHA256",
    "AttachmentCount",
    "AttachmentNames",
    "AttachmentSizes",
    "AttachmentSHA256s",
    "AttachmentExtractedPaths",
    "HasAttachments",
    "SourcePath",
]


# ---------------------------------------------------------------------------
# Step 1: run pffexport to crack the PST open
# ---------------------------------------------------------------------------
def check_pffexport():
    if shutil.which("pffexport") is None:
        sys.exit(
            "ERROR: pffexport not found. Install it with:\n"
            "    sudo apt install -y pff-tools libpff-dev\n"
        )


def run_pffexport(pst_path, export_dir):
    """
    Call pffexport to extract the PST. Many evidence PSTs have minor
    corruption (truncated/edited), so we try modes in order of strictness:
        1. 'items'     — just the allocated, healthy items
        2. 'recovered' — orphaned and recovered items (writes to .recovered/)
        3. 'all'       — both, but bails on the first bad offset
    'items' + 'recovered' separately is more resilient than 'all'.
    """
    print(f"[+] Running pffexport on: {pst_path}")

    def _try(mode):
        cmd = [
            "pffexport",
            "-m", mode,
            "-f", "all",       # text + html + rtf bodies
            "-q",              # quiet
            "-t", str(export_dir),
            str(pst_path),
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    # Pass 1: allocated items
    r1 = _try("items")
    if r1.returncode != 0:
        print(f"    'items' mode failed, trying 'recovered' mode...")
        print(f"    libpff said: {r1.stderr.strip().splitlines()[-1] if r1.stderr else '(no detail)'}")
    else:
        print(f"    [\u2713] 'items' mode succeeded")

    # Pass 2: also grab orphans/recovered (writes to <export_dir>.recovered/)
    r2 = _try("recovered")
    if r2.returncode != 0:
        print(f"    'recovered' mode: no recoverable items (this is normal)")
    else:
        print(f"    [\u2713] 'recovered' mode succeeded — orphans written too")

    # If BOTH failed, we're stuck
    if r1.returncode != 0 and r2.returncode != 0:
        sys.exit(
            "ERROR: pffexport failed in both items and recovered modes.\n"
            f"items mode: {r1.stderr.strip()}\n"
            f"recovered mode: {r2.stderr.strip()}"
        )

    print(f"[+] Export complete")


# ---------------------------------------------------------------------------
# Step 2: walk the exported tree
# ---------------------------------------------------------------------------
def find_message_dirs(export_root):
    """
    pffexport lays out messages like:
        <export_root>.export/
            Folder Name/
                Message00001/
                    InternetHeaders.txt
                    Message.txt        (plain body)
                    Message.html       (html body, if any)
                    Message.rtf        (rtf body, if any)
                    OutlookHeaders.txt (Outlook metadata)
                    Recipients.txt
                    Attachments/
        <export_root>.recovered/   (only if recovered mode found orphans)
            Recovered/
                Message00001/
                ...

    We scan BOTH directories so recovered items also land in the CSV.
    """
    # Find every dir that starts with our export_root basename and has a known suffix
    candidates = list(export_root.parent.glob(export_root.name + ".*"))
    roots = [c for c in candidates if c.is_dir() and
             (c.name.endswith(".export") or c.name.endswith(".recovered")
              or c.name.endswith(".orphans"))]

    if not roots:
        # fall back to anything matching
        roots = [c for c in candidates if c.is_dir()]
    if not roots:
        sys.exit(f"ERROR: could not locate pffexport output near {export_root}")

    print(f"[+] Scanning {len(roots)} export tree(s): {[r.name for r in roots]}")

    msg_dirs = []
    primary_root = None
    for root in roots:
        if primary_root is None:
            primary_root = root  # used for relative-path display in CSV
        # Any directory containing InternetHeaders.txt OR OutlookHeaders.txt is a message
        for path in root.rglob("*"):
            if path.is_dir() and (
                (path / "InternetHeaders.txt").exists()
                or (path / "OutlookHeaders.txt").exists()
            ):
                msg_dirs.append(path)
    msg_dirs.sort()
    return primary_root, msg_dirs


# ---------------------------------------------------------------------------
# Step 3: parse one message directory
# ---------------------------------------------------------------------------
def read_text(path):
    """Read a file with encoding fallbacks; return '' on miss."""
    if not path.exists():
        return ""
    raw = path.read_bytes()
    for enc in ("utf-8", "utf-16", "latin-1", "cp1252"):
        try:
            return raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").strip()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest() if data else ""


def sanitize_filename(name, fallback="attachment"):
    if not name:
        return fallback
    name = re.sub(r"[\x00-\x1f]", "", name)
    name = re.sub(r'[/\\:*?"<>|]', "_", name)
    return name.strip(" .") or fallback


def parse_internet_headers(text):
    """Parse RFC822 headers via Python's email module."""
    if not text:
        return {}
    try:
        msg = BytesParser(policy=policy.default).parsebytes(text.encode("utf-8", errors="replace"))
        out = {}
        for key in ("From", "To", "Cc", "Bcc", "Reply-To", "Subject",
                    "Date", "Message-ID", "Importance", "Priority",
                    "Sensitivity", "Thread-Topic", "Thread-Index"):
            val = msg.get(key)
            if val:
                out[key] = str(val).strip()
        return out
    except Exception:
        return {}


def parse_outlook_headers(text):
    """
    Parse pffexport's OutlookHeaders.txt — a key: value listing of MAPI props.
    Keys vary by Outlook version, so we grab whatever's there.
    """
    if not text:
        return {}
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if k and v:
                out[k] = v
    return out


def parse_recipients(text):
    """Recipients.txt has To/Cc/Bcc grouped. Return three joined strings."""
    if not text:
        return "", "", ""
    to_list, cc_list, bcc_list = [], [], []
    current = None
    for line in text.splitlines():
        lower = line.strip().lower()
        if lower.startswith("recipient type") or lower.startswith("type:"):
            if "bcc" in lower:
                current = bcc_list
            elif "cc" in lower:
                current = cc_list
            else:
                current = to_list
        elif lower.startswith("display name:") and current is not None:
            current.append(line.split(":", 1)[1].strip())
        elif lower.startswith("email address:") and current is not None:
            # append email to the last display name
            email = line.split(":", 1)[1].strip()
            if current and "@" not in current[-1]:
                current[-1] = f"{current[-1]} <{email}>"
            else:
                current.append(email)
    return "; ".join(to_list), "; ".join(cc_list), "; ".join(bcc_list)


def extract_attachments(msg_dir, msg_num, attachments_root):
    """Copy any attachments out, hash them, return parallel lists."""
    names, sizes, hashes, paths = [], [], [], []
    src_att_dir = msg_dir / "Attachments"
    if not src_att_dir.exists() or not src_att_dir.is_dir():
        return names, sizes, hashes, paths

    dest_dir = attachments_root / f"msg_{msg_num:06d}"
    for att in sorted(src_att_dir.iterdir()):
        if not att.is_file():
            continue
        clean_name = sanitize_filename(att.name)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / clean_name

        # handle name collisions
        counter = 1
        while dest_path.exists():
            stem, suffix = dest_path.stem, dest_path.suffix
            dest_path = dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        try:
            data = att.read_bytes()
            dest_path.write_bytes(data)
            names.append(clean_name)
            sizes.append(str(len(data)))
            hashes.append(sha256_bytes(data))
            paths.append(str(dest_path))
        except Exception as exc:
            names.append(f"<error:{exc}>")
            sizes.append("")
            hashes.append("")
            paths.append("")

    return names, sizes, hashes, paths


def parse_message_dir(msg_dir, export_root, msg_num, attachments_root):
    """Build one CSV row from a pffexport message directory."""
    internet_headers_raw = read_text(msg_dir / "InternetHeaders.txt")
    outlook_headers_raw  = read_text(msg_dir / "OutlookHeaders.txt")
    body_plain           = read_text(msg_dir / "Message.txt")
    has_html             = (msg_dir / "Message.html").exists()
    has_rtf              = (msg_dir / "Message.rtf").exists()
    recipients_raw       = read_text(msg_dir / "Recipients.txt")

    ih = parse_internet_headers(internet_headers_raw)
    oh = parse_outlook_headers(outlook_headers_raw)
    to_str, cc_str, bcc_str = parse_recipients(recipients_raw)

    body_bytes = body_plain.encode("utf-8", errors="replace")

    att_names, att_sizes, att_hashes, att_paths = extract_attachments(
        msg_dir, msg_num, attachments_root
    )

    # folder = relative path from the export root, minus the message dir itself
    try:
        folder_rel = msg_dir.relative_to(export_root).parent
        folder_str = str(folder_rel) if str(folder_rel) != "." else "(root)"
    except ValueError:
        folder_str = str(msg_dir.parent)

    return {
        "MessageNumber": msg_num,
        "Folder": folder_str,
        "InternetMessageID": ih.get("Message-ID", ""),
        "Subject": ih.get("Subject") or oh.get("Subject", ""),
        "From": ih.get("From") or oh.get("Sender Name", "") or oh.get("From", ""),
        "To": to_str or ih.get("To", ""),
        "Cc": cc_str or ih.get("Cc", ""),
        "Bcc": bcc_str or ih.get("Bcc", ""),
        "ReplyTo": ih.get("Reply-To", ""),
        "DateSent": ih.get("Date", "") or oh.get("Client submit time", ""),
        "DateReceived": oh.get("Delivery time", "") or oh.get("Message delivery time", ""),
        "DateCreation": oh.get("Creation time", ""),
        "DateModification": oh.get("Modification time", ""),
        "ClientSubmitTime": oh.get("Client submit time", ""),
        "DeliveryTime": oh.get("Delivery time", "") or oh.get("Message delivery time", ""),
        "Importance": ih.get("Importance", "") or oh.get("Importance", ""),
        "Priority": ih.get("Priority", "") or oh.get("Priority", ""),
        "Sensitivity": ih.get("Sensitivity", "") or oh.get("Sensitivity", ""),
        "MessageClass": oh.get("Message class", ""),
        "ConversationTopic": ih.get("Thread-Topic", "") or oh.get("Conversation topic", ""),
        "ConversationIndex": ih.get("Thread-Index", "") or oh.get("Conversation index", ""),
        "TransportHeaders": internet_headers_raw,
        "BodyPlain": body_plain,
        "BodyHTMLPresent": "yes" if has_html else "no",
        "BodyRTFPresent": "yes" if has_rtf else "no",
        "BodySize": len(body_bytes),
        "BodySHA256": sha256_bytes(body_bytes),
        "AttachmentCount": len(att_names),
        "AttachmentNames": " | ".join(att_names),
        "AttachmentSizes": " | ".join(att_sizes),
        "AttachmentSHA256s": " | ".join(att_hashes),
        "AttachmentExtractedPaths": " | ".join(att_paths),
        "HasAttachments": "yes" if att_names else "no",
        "SourcePath": str(msg_dir),
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def convert(pst_path, csv_path, attachments_dir, keep_export):
    pst_path = Path(pst_path).resolve()
    csv_path = Path(csv_path).resolve()
    attachments_dir = Path(attachments_dir).resolve()

    if not pst_path.exists():
        sys.exit(f"ERROR: PST file not found: {pst_path}")

    check_pffexport()
    attachments_dir.mkdir(parents=True, exist_ok=True)

    # Hash the source PST for chain of custody
    print(f"[+] Hashing source PST...")
    pst_sha = hashlib.sha256(pst_path.read_bytes()).hexdigest()
    print(f"    SHA-256: {pst_sha}")

    # Export PST to temp staging dir
    if keep_export:
        export_root = pst_path.parent / "_pff_export"
        if export_root.exists():
            shutil.rmtree(export_root)
        export_root.mkdir()
    else:
        tmp = tempfile.mkdtemp(prefix="pff_export_")
        export_root = Path(tmp) / "export"

    try:
        run_pffexport(pst_path, export_root)
        actual_root, msg_dirs = find_message_dirs(export_root)

        print(f"[+] Found {len(msg_dirs)} messages")
        print(f"[+] Writing CSV: {csv_path}")

        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=CSV_COLUMNS,
                quoting=csv.QUOTE_ALL,
                extrasaction="ignore",
            )
            writer.writeheader()

            for msg_num, msg_dir in enumerate(msg_dirs, start=1):
                try:
                    row = parse_message_dir(msg_dir, actual_root, msg_num, attachments_dir)
                    writer.writerow(row)
                except Exception as exc:
                    print(f"    ! error on message {msg_num} ({msg_dir.name}): {exc}")
                    continue

                if msg_num % 100 == 0:
                    print(f"    ... {msg_num} processed")

        print(f"\n[\u2713] Done.")
        print(f"    Source PST:        {pst_path}")
        print(f"    Source SHA-256:    {pst_sha}")
        print(f"    Messages exported: {len(msg_dirs)}")
        print(f"    CSV:               {csv_path}")
        print(f"    Attachments dir:   {attachments_dir}")
        if keep_export:
            print(f"    Raw export tree:   {actual_root}  (kept)")

    finally:
        if not keep_export:
            shutil.rmtree(export_root.parent, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="Forensic PST-to-CSV converter (Kali arm64, uses pffexport)."
    )
    parser.add_argument("pst", help="Path to input .pst file")
    parser.add_argument("csv", help="Path to output .csv file")
    parser.add_argument(
        "--attachments-dir",
        default="attachments",
        help="Where to extract attachments (default: ./attachments)",
    )
    parser.add_argument(
        "--keep-export",
        action="store_true",
        help="Keep the intermediate pffexport tree for inspection",
    )
    args = parser.parse_args()
    convert(args.pst, args.csv, args.attachments_dir, args.keep_export)


if __name__ == "__main__":
    main()
