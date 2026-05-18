import os
import json
import sqlite3
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "leakrecon.db")

_lock = threading.Lock()


def _ensure_dir() -> None:
    """Ensures that the directory for the SQLite database exists."""
    os.makedirs(DB_DIR, exist_ok=True)


def _get_connection() -> sqlite3.Connection:
    """
    Creates and returns a SQLite connection optimized for concurrency.
    Enforces Write-Ahead Logging (WAL) and explicit foreign key constraints.
    
    Returns:
        sqlite3.Connection: A configured SQLite database connection.
    """
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initializes the database schema if it does not already exist.
    Creates tables for scans and scan_results, along with appropriate indices.
    """
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
    """
    Consolidates scan results and persists them into the database.
    
    Args:
        target (str): The target identifier (IP, domain, etc.).
        category (str): The category of the scan (e.g., 'Darkweb', 'Identity').
        results (list): Raw list of ScanResult objects.
        elapsed (float): Time taken to complete the scan in seconds.
        
    Returns:
        int: The unique identifier (scan_id) of the newly inserted record.
    """
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


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves the chronological scan history.
    
    Args:
        limit (int): The maximum number of records to retrieve.
        
    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing scan metadata.
    """
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


def get_scan_detail(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieves complete details for a specific scan, including all results.
    
    Args:
        scan_id (int): The unique identifier of the scan.
        
    Returns:
        Optional[Dict[str, Any]]: A dictionary combining scan metadata and findings,
        or None if not found.
    """
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


def get_target_history(target: str) -> List[Dict[str, Any]]:
    """
    Retrieves the chronological history of scans executed against a specific target.
    
    Args:
        target (str): The specific target identifier.
        
    Returns:
        List[Dict[str, Any]]: A list of scan metadata dictionaries.
    """
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


def get_scan_diff(target: str) -> Optional[Dict[str, Any]]:
    """
    Performs a differential analysis between the two most recent scans of a target.
    
    Args:
        target (str): The target identifier to analyze.
        
    Returns:
        Optional[Dict[str, Any]]: Differential results including resolved, new, and
        unchanged findings, or None if insufficient history exists.
    """
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


def get_stats() -> Dict[str, Any]:
    """
    Aggregates global system statistics for operational oversight.
    
    Returns:
        Dict[str, Any]: Application metrics including scan volumes and category distribution.
    """
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


def clear_history() -> None:
    """
    Purges all operational data from the system database and attempts vacuuming.
    Used for compliance and data retention lifecycle management.
    """
    with _lock:
        conn = _get_connection()
        try:
            conn.execute("DELETE FROM scan_results")
            conn.execute("DELETE FROM scans")
            try:
                conn.execute("VACUUM")
            except sqlite3.OperationalError:
                # VACUUM requires an exclusive lock and cannot run inside a transaction
                pass
            conn.commit()
        finally:
            conn.close()
