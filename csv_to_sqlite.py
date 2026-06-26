#!/usr/bin/env python3
"""
csv_to_sqlite.py — Import the forensic CSV into a queryable SQLite database
============================================================================
Takes the eric_saibi_chris.csv output from pst_to_csv.py and loads it into
a properly-typed SQLite database with indexes and convenience views for
forensic analysis.

Usage:
    python3 csv_to_sqlite.py eric_saibi_chris.csv eric_saibi.db

Then query with:
    sqlite3 eric_saibi.db
"""

import argparse
import csv
import sqlite3
import sys
from pathlib import Path


SCHEMA = """
DROP TABLE IF EXISTS messages;

CREATE TABLE messages (
    MessageNumber             INTEGER PRIMARY KEY,
    Folder                    TEXT,
    InternetMessageID         TEXT,
    Subject                   TEXT,
    "From"                    TEXT,
    "To"                      TEXT,
    Cc                        TEXT,
    Bcc                       TEXT,
    ReplyTo                   TEXT,
    DateSent                  TEXT,
    DateReceived              TEXT,
    DateCreation              TEXT,
    DateModification          TEXT,
    ClientSubmitTime          TEXT,
    DeliveryTime              TEXT,
    Importance                TEXT,
    Priority                  TEXT,
    Sensitivity               TEXT,
    MessageClass              TEXT,
    ConversationTopic         TEXT,
    ConversationIndex         TEXT,
    TransportHeaders          TEXT,
    BodyPlain                 TEXT,
    BodyHTMLPresent           TEXT,
    BodyRTFPresent            TEXT,
    BodySize                  INTEGER,
    BodySHA256                TEXT,
    AttachmentCount           INTEGER,
    AttachmentNames           TEXT,
    AttachmentSizes           TEXT,
    AttachmentSHA256s         TEXT,
    AttachmentExtractedPaths  TEXT,
    HasAttachments            TEXT,
    SourcePath                TEXT
);

-- Indexes on commonly-queried columns
CREATE INDEX idx_folder       ON messages(Folder);
CREATE INDEX idx_from         ON messages("From");
CREATE INDEX idx_subject      ON messages(Subject);
CREATE INDEX idx_has_att      ON messages(HasAttachments);
CREATE INDEX idx_date_sent    ON messages(DateSent);
CREATE INDEX idx_msgclass     ON messages(MessageClass);

-- Full-text search index over subject + body + headers
DROP TABLE IF EXISTS messages_fts;
CREATE VIRTUAL TABLE messages_fts USING fts5(
    Subject, BodyPlain, TransportHeaders, "From", "To",
    content='messages', content_rowid='MessageNumber'
);

-- Keep FTS in sync (trigger fires when we insert)
CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, Subject, BodyPlain, TransportHeaders, "From", "To")
    VALUES (new.MessageNumber, new.Subject, new.BodyPlain, new.TransportHeaders, new."From", new."To");
END;
"""

# Convenience views for common forensic queries
VIEWS = """
-- Messages with attachments
DROP VIEW IF EXISTS v_with_attachments;
CREATE VIEW v_with_attachments AS
SELECT MessageNumber, DateSent, "From", "To", Subject,
       AttachmentCount, AttachmentNames
FROM messages
WHERE HasAttachments = 'yes'
ORDER BY DateSent;

-- Top senders
DROP VIEW IF EXISTS v_top_senders;
CREATE VIEW v_top_senders AS
SELECT "From" AS sender, COUNT(*) AS msg_count
FROM messages
WHERE "From" != ''
GROUP BY "From"
ORDER BY msg_count DESC;

-- Top recipients
DROP VIEW IF EXISTS v_top_recipients;
CREATE VIEW v_top_recipients AS
SELECT "To" AS recipient, COUNT(*) AS msg_count
FROM messages
WHERE "To" != ''
GROUP BY "To"
ORDER BY msg_count DESC;

-- Folder distribution
DROP VIEW IF EXISTS v_folder_stats;
CREATE VIEW v_folder_stats AS
SELECT Folder, COUNT(*) AS msg_count, SUM(AttachmentCount) AS total_attachments
FROM messages
GROUP BY Folder
ORDER BY msg_count DESC;

-- Messages summary (slim columns, easy on the eyes)
DROP VIEW IF EXISTS v_summary;
CREATE VIEW v_summary AS
SELECT MessageNumber, DateSent, "From", "To", Subject, HasAttachments
FROM messages
ORDER BY MessageNumber;
"""


def main():
    parser = argparse.ArgumentParser(description="Import forensic CSV into SQLite.")
    parser.add_argument("csv_path", help="Input CSV from pst_to_csv.py")
    parser.add_argument("db_path", help="Output SQLite database file")
    args = parser.parse_args()

    csv_path = Path(args.csv_path).resolve()
    db_path = Path(args.db_path).resolve()

    if not csv_path.exists():
        sys.exit(f"ERROR: CSV not found: {csv_path}")

    if db_path.exists():
        print(f"[!] Removing existing DB: {db_path}")
        db_path.unlink()

    print(f"[+] Creating database: {db_path}")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA)

    print(f"[+] Loading CSV: {csv_path}")
    # Bump CSV field limit — body fields can be large
    csv.field_size_limit(sys.maxsize)

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames
        placeholders = ",".join("?" for _ in cols)
        col_list = ",".join(f'"{c}"' for c in cols)
        sql = f'INSERT INTO messages ({col_list}) VALUES ({placeholders})'

        count = 0
        batch = []
        for row in reader:
            batch.append(tuple(row[c] for c in cols))
            count += 1
            if len(batch) >= 500:
                cur.executemany(sql, batch)
                batch.clear()
        if batch:
            cur.executemany(sql, batch)

    print(f"[+] Inserted {count} messages")
    print(f"[+] Building views...")
    cur.executescript(VIEWS)

    conn.commit()

    # Sanity stats
    stats = {
        "messages":          cur.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
        "with attachments":  cur.execute("SELECT COUNT(*) FROM messages WHERE HasAttachments='yes'").fetchone()[0],
        "unique senders":    cur.execute("SELECT COUNT(DISTINCT \"From\") FROM messages WHERE \"From\"!=''").fetchone()[0],
        "unique folders":    cur.execute("SELECT COUNT(DISTINCT Folder) FROM messages").fetchone()[0],
        "total attachments": cur.execute("SELECT SUM(AttachmentCount) FROM messages").fetchone()[0],
    }
    conn.close()

    print(f"\n[\u2713] Done.")
    for k, v in stats.items():
        print(f"    {k:<20} {v}")
    print(f"\n    Database: {db_path}")
    print(f"    Query it:  sqlite3 {db_path}")


if __name__ == "__main__":
    main()
