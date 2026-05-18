import os
import json
import sqlite3
import threading
from datetime import datetime
from dataclasses import asdict

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "leakrecon.db")

_lock = threading.Lock()


def _ensure_dir():
    os.makedirs(DB_DIR, exist_ok=True)


def _get_connection() -> sqlite3.Connection:
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = _get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT    NOT NULL,
                    category    TEXT    NOT NULL,
                    timestamp   TEXT    NOT NULL,
                    duration    REAL    NOT NULL DEFAULT 0,
                    source_count INTEGER NOT NULL DEFAULT 0,
                    query_count  INTEGER NOT NULL DEFAULT 0,
                    found_count  INTEGER NOT NULL DEFAULT 0,
                    clean_count  INTEGER NOT NULL DEFAULT 0,
                    error_count  INTEGER NOT NULL DEFAULT 0,
                    skipped_count INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER NOT NULL,
                    source_name TEXT    NOT NULL,
                    source_url  TEXT,
                    found       INTEGER NOT NULL DEFAULT 0,
                    snippets    TEXT,
                    error       TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
                CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id);
            """)
            conn.commit()
        finally:
            conn.close()


def save_scan(target: str, category: str, results: list, elapsed: float = 0) -> int:
    from modules.darkweb_scraper import _consolidate_results

    consolidated = _consolidate_results(results)

    found = sum(1 for r in consolidated if r.found)
    clean = sum(1 for r in consolidated if not r.found and not r.error)
    errors = sum(1 for r in consolidated if r.error and "Atlandı" not in (r.error or ""))
    skipped = sum(1 for r in consolidated if r.error and "Atlandı" in (r.error or ""))

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _lock:
        conn = _get_connection()
        try:
            cursor = conn.execute(
                """INSERT INTO scans (target, category, timestamp, duration,
                   source_count, query_count, found_count, clean_count,
                   error_count, skipped_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (target, category, ts, elapsed,
                 len(consolidated), len(results),
                 found, clean, errors, skipped),
            )
            scan_id = cursor.lastrowid

            for r in consolidated:
                conn.execute(
                    """INSERT INTO scan_results
                       (scan_id, source_name, source_url, found, snippets, error)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (scan_id, r.source_name, r.source_url,
                     1 if r.found else 0,
                     json.dumps(r.matched_snippets, ensure_ascii=False) if r.matched_snippets else None,
                     r.error),
                )
            conn.commit()
        finally:
            conn.close()

    return scan_id


def get_history(limit: int = 50) -> list[dict]:
    with _lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                """SELECT id, target, category, timestamp, duration,
                          source_count, query_count, found_count,
                          clean_count, error_count, skipped_count
                   FROM scans ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        finally:
            conn.close()
    return [dict(r) for r in rows]


def get_scan_detail(scan_id: int) -> dict | None:
    with _lock:
        conn = _get_connection()
        try:
            scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not scan:
                return None
            results = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
        finally:
            conn.close()

    return {
        "scan": dict(scan),
        "results": [dict(r) for r in results],
    }


def get_target_history(target: str) -> list[dict]:
    with _lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                """SELECT id, target, category, timestamp, duration,
                          found_count, clean_count, error_count
                   FROM scans WHERE target = ? ORDER BY id DESC""",
                (target,),
            ).fetchall()
        finally:
            conn.close()
    return [dict(r) for r in rows]


def get_scan_diff(target: str) -> dict | None:
    scans = get_target_history(target)
    if len(scans) < 2:
        return None

    latest_id = scans[0]["id"]
    previous_id = scans[1]["id"]

    latest_detail = get_scan_detail(latest_id)
    previous_detail = get_scan_detail(previous_id)

    if not latest_detail or not previous_detail:
        return None

    prev_sources = {r["source_name"]: r for r in previous_detail["results"]}
    curr_sources = {r["source_name"]: r for r in latest_detail["results"]}

    new_findings = []
    resolved = []
    unchanged = []

    for name, curr in curr_sources.items():
        prev = prev_sources.get(name)
        if curr["found"] and (not prev or not prev["found"]):
            new_findings.append(curr)
        elif not curr["found"] and prev and prev["found"]:
            resolved.append(curr)
        else:
            unchanged.append(curr)

    return {
        "latest": latest_detail["scan"],
        "previous": previous_detail["scan"],
        "new_findings": new_findings,
        "resolved": resolved,
        "unchanged": unchanged,
    }


def get_stats() -> dict:
    with _lock:
        conn = _get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
            found_total = conn.execute("SELECT SUM(found_count) as c FROM scans").fetchone()["c"] or 0
            unique_targets = conn.execute("SELECT COUNT(DISTINCT target) as c FROM scans").fetchone()["c"]
            categories = conn.execute(
                "SELECT category, COUNT(*) as c FROM scans GROUP BY category ORDER BY c DESC"
            ).fetchall()
        finally:
            conn.close()

    return {
        "total_scans": total,
        "total_findings": found_total,
        "unique_targets": unique_targets,
        "categories": [dict(c) for c in categories],
    }


def clear_history():
    with _lock:
        conn = _get_connection()
        try:
            conn.execute("DELETE FROM scan_results")
            conn.execute("DELETE FROM scans")
            try:
                conn.execute("VACUUM")
            except sqlite3.OperationalError:
                # VACUUM requires exclusive lock; ignore if failed
                pass
            conn.commit()
        finally:
            conn.close()
