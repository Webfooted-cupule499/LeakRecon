import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from core import database as db

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


def _ensure_dir() -> None:
    """Ensures the reports output directory exists."""
    os.makedirs(REPORT_DIR, exist_ok=True)


def export_json(scan_ids: Optional[List[int]] = None) -> str:
    """
    Exports scan data to a JSON file.
    
    Args:
        scan_ids (Optional[List[int]]): Specific scan IDs to export. Exports all if None.
        
    Returns:
        str: The absolute path to the generated JSON file.
    """
    _ensure_dir()
    fname = f"leakrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(REPORT_DIR, fname)

    if scan_ids:
        data = [db.get_scan_detail(sid) for sid in scan_ids]
        data = [d for d in data if d]
    else:
        history = db.get_history(limit=500)
        data = []
        for scan in history:
            detail = db.get_scan_detail(scan["id"])
            if detail:
                data.append(detail)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return path


def export_csv(scan_ids: Optional[List[int]] = None) -> str:
    """
    Exports scan data to a CSV file.
    
    Args:
        scan_ids (Optional[List[int]]): Specific scan IDs to export. Exports all if None.
        
    Returns:
        str: The absolute path to the generated CSV file.
    """
    _ensure_dir()
    fname = f"leakrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    path = os.path.join(REPORT_DIR, fname)

    if scan_ids:
        scans = [db.get_scan_detail(sid) for sid in scan_ids]
        scans = [s for s in scans if s]
    else:
        history = db.get_history(limit=500)
        scans = []
        for scan in history:
            detail = db.get_scan_detail(scan["id"])
            if detail:
                scans.append(detail)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Scan ID", "Target", "Category", "Timestamp", "Duration (s)",
            "Source", "Status", "Matches", "Error",
        ])

        for scan_data in scans:
            scan = scan_data["scan"]
            for r in scan_data["results"]:
                status = "FOUND" if r["found"] else ("ERROR" if r["error"] else "CLEAN")
                snippets = ""
                if r["snippets"]:
                    try:
                        snippets = " | ".join(json.loads(r["snippets"]))
                    except Exception:
                        snippets = r["snippets"]
                writer.writerow([
                    scan["id"], scan["target"], scan["category"],
                    scan["timestamp"], f"{scan['duration']:.1f}",
                    r["source_name"], status, snippets, r["error"] or "",
                ])

    return path


def export_html(scan_ids: Optional[List[int]] = None) -> str:
    """
    Generates an enterprise-grade HTML intelligence report with executive summary,
    findings breakdown, and technical details sections.
    
    Args:
        scan_ids (Optional[List[int]]): Specific scan IDs to include. Includes all if None.
        
    Returns:
        str: The absolute path to the generated HTML report.
    """
    _ensure_dir()
    fname = f"leakrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    path = os.path.join(REPORT_DIR, fname)

    if scan_ids:
        scans = [db.get_scan_detail(sid) for sid in scan_ids]
        scans = [s for s in scans if s]
    else:
        history = db.get_history(limit=100)
        scans = []
        for scan in history:
            detail = db.get_scan_detail(scan["id"])
            if detail:
                scans.append(detail)

    stats = db.get_stats()
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_findings = sum(s["scan"]["found_count"] for s in scans)
    total_errors = sum(s["scan"]["error_count"] for s in scans)
    total_clean = sum(s["scan"]["clean_count"] for s in scans)
    risk_level = "CRITICAL" if total_findings > 10 else ("HIGH" if total_findings > 5 else ("MEDIUM" if total_findings > 0 else "LOW"))
    risk_color = "#ff3838" if risk_level in ("CRITICAL", "HIGH") else ("#ffb700" if risk_level == "MEDIUM" else "#00ff88")

    # Build scan detail blocks
    scan_blocks = []
    for scan_data in scans:
        scan = scan_data["scan"]
        rows = []
        for idx, r in enumerate(scan_data["results"], 1):
            if r["found"]:
                status_class = "status-found"
                status_text = "FOUND"
            elif r["error"] and "Atlandı" in (r["error"] or ""):
                status_class = "status-skipped"
                status_text = "UNREACHABLE"
            elif r["error"]:
                status_class = "status-error"
                status_text = "ERROR"
            else:
                status_class = "status-clean"
                status_text = "CLEAN"

            detail = ""
            if r["found"] and r["snippets"]:
                try:
                    snips = json.loads(r["snippets"])
                    detail = "<br>".join(_escape(s) for s in snips[:5])
                except Exception:
                    detail = _escape(r["snippets"])
            elif r["error"]:
                detail = _escape(r["error"])
            else:
                detail = "No match detected"

            rows.append(f"""
                <tr>
                    <td class="center">{idx}</td>
                    <td class="source">{_escape(r['source_name'])}</td>
                    <td class="center {status_class}">{status_text}</td>
                    <td class="detail">{detail}</td>
                </tr>""")

        scan_blocks.append(f"""
        <div class="scan-block">
            <div class="scan-header">
                <h3>{_escape(scan['category'])}</h3>
                <span class="scan-time">{_escape(scan['timestamp'])}</span>
            </div>
            <div class="scan-meta">
                <div class="meta-item"><span class="label">Target</span><span class="value">{_escape(scan['target'])}</span></div>
                <div class="meta-item"><span class="label">Duration</span><span class="value">{scan['duration']:.1f}s</span></div>
                <div class="meta-item"><span class="label">Sources</span><span class="value">{scan['source_count']}</span></div>
                <div class="meta-item"><span class="label">Queries</span><span class="value">{scan['query_count']}</span></div>
            </div>
            <div class="scan-stats">
                <span class="stat stat-found">Findings: {scan['found_count']}</span>
                <span class="stat stat-clean">Clean: {scan['clean_count']}</span>
                <span class="stat stat-error">Errors: {scan['error_count']}</span>
                <span class="stat stat-skipped">Skipped: {scan['skipped_count']}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th class="center" style="width:40px">#</th>
                        <th style="width:160px">Source</th>
                        <th class="center" style="width:120px">Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>""")

    # Unique targets list for executive summary
    unique_targets = list(set(s["scan"]["target"] for s in scans))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LeakRecon — Intelligence Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif;
            background: #0a0e17;
            color: #c8d6e5;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}

        /* Header */
        .header {{
            text-align: center;
            padding: 48px 0 32px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.15);
            margin-bottom: 40px;
        }}
        .header h1 {{
            font-size: 2.2em;
            background: linear-gradient(135deg, #00ff88, #00d4ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 3px;
            margin-bottom: 8px;
        }}
        .header .subtitle {{
            color: #5a6c7d;
            font-size: 0.95em;
            letter-spacing: 1px;
        }}
        .header .generated {{
            color: #3a4a5a;
            font-size: 0.85em;
            margin-top: 16px;
        }}
        .header .classification {{
            display: inline-block;
            margin-top: 12px;
            padding: 4px 16px;
            border: 1px solid #ff3838;
            color: #ff3838;
            font-size: 0.75em;
            letter-spacing: 2px;
            border-radius: 4px;
        }}

        /* Section Headers */
        .section-title {{
            font-size: 1.3em;
            color: #00d4ff;
            margin: 40px 0 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #1e2d3d;
            letter-spacing: 1px;
        }}

        /* Executive Summary */
        .executive-summary {{
            background: linear-gradient(135deg, #111827, #1a2332);
            border: 1px solid #1e2d3d;
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 32px;
        }}
        .executive-summary p {{
            margin-bottom: 12px;
            color: #a0b0c0;
            font-size: 0.95em;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 6px 20px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.9em;
            letter-spacing: 1px;
            color: #fff;
        }}
        .target-list {{
            list-style: none;
            padding: 0;
            margin-top: 12px;
        }}
        .target-list li {{
            padding: 4px 0;
            color: #c8d6e5;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .target-list li::before {{
            content: "\\25B8  ";
            color: #00d4ff;
        }}

        /* Stats Overview */
        .overview {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 40px;
        }}
        .overview-card {{
            background: linear-gradient(135deg, #111827, #1a2332);
            border: 1px solid #1e2d3d;
            border-radius: 12px;
            padding: 24px;
            text-align: center;
        }}
        .overview-card .number {{
            font-size: 2em;
            font-weight: 700;
            color: #00ff88;
        }}
        .overview-card .label {{
            font-size: 0.85em;
            color: #5a6c7d;
            margin-top: 4px;
        }}

        /* Scan Blocks */
        .scan-block {{
            background: #111827;
            border: 1px solid #1e2d3d;
            border-radius: 12px;
            margin-bottom: 28px;
            overflow: hidden;
        }}
        .scan-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            background: linear-gradient(135deg, #0f1923, #162030);
            border-bottom: 1px solid #1e2d3d;
        }}
        .scan-header h3 {{ font-size: 1.1em; color: #e2e8f0; }}
        .scan-time {{ color: #5a6c7d; font-size: 0.85em; }}
        .scan-meta {{
            display: flex;
            gap: 32px;
            padding: 16px 24px;
            border-bottom: 1px solid #1a2535;
        }}
        .meta-item .label {{ color: #5a6c7d; font-size: 0.8em; display: block; }}
        .meta-item .value {{ color: #e2e8f0; font-weight: 600; }}
        .scan-stats {{
            display: flex;
            gap: 16px;
            padding: 12px 24px;
            border-bottom: 1px solid #1a2535;
        }}
        .stat {{
            font-size: 0.85em;
            padding: 4px 14px;
            border-radius: 20px;
            font-weight: 600;
        }}
        .stat-found {{ background: rgba(255, 56, 56, 0.15); color: #ff5555; }}
        .stat-clean {{ background: rgba(0, 255, 136, 0.1); color: #00ff88; }}
        .stat-error {{ background: rgba(255, 183, 0, 0.1); color: #ffb700; }}
        .stat-skipped {{ background: rgba(100, 120, 140, 0.15); color: #7a8a9a; }}

        /* Table */
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            text-align: left;
            padding: 12px 16px;
            background: #0d1520;
            color: #00d4ff;
            font-size: 0.85em;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px 16px;
            border-top: 1px solid #1a2535;
            font-size: 0.9em;
            vertical-align: top;
        }}
        tr:hover td {{ background: rgba(0, 212, 255, 0.03); }}
        .center {{ text-align: center; }}
        .source {{ font-weight: 600; color: #e2e8f0; }}
        .detail {{ color: #7a8a9a; font-size: 0.85em; word-break: break-all; }}
        .status-found {{ color: #ff5555; font-weight: 700; }}
        .status-clean {{ color: #00ff88; }}
        .status-error {{ color: #ffb700; }}
        .status-skipped {{ color: #5a6c7d; }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 32px 0;
            margin-top: 40px;
            border-top: 1px solid rgba(0, 255, 136, 0.1);
            color: #3a4a5a;
            font-size: 0.8em;
        }}

        @media print {{
            body {{ background: #fff; color: #333; }}
            .scan-block {{ border-color: #ddd; background: #fff; color: #333; }}
            .scan-header {{ background: #f0f0f0; border-color: #ddd; }}
            .scan-header h3 {{ color: #333; }}
            table {{ border: 1px solid #ddd; }}
            th {{ background: #f0f0f0; color: #333; border-bottom: 2px solid #ddd; }}
            td {{ border-top: 1px solid #ddd; color: #333; }}
            .source {{ color: #333; }}
            .detail {{ color: #555; }}
            .header h1 {{ color: #1a1a1a; -webkit-text-fill-color: #1a1a1a; }}
            .overview-card {{ background: #fff; border-color: #ddd; }}
            .overview-card .number {{ color: #333; }}
            .overview-card .label {{ color: #666; }}
            .executive-summary {{ background: #f8f8f8; border-color: #ddd; }}
            .executive-summary p {{ color: #333; }}
            .section-title {{ color: #333; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LEAKRECON</h1>
            <div class="subtitle">Dark Web Leak Intelligence Report</div>
            <div class="classification">CONFIDENTIAL</div>
            <div class="generated">Generated: {generated}</div>
        </div>

        <!-- SECTION 1: EXECUTIVE SUMMARY -->
        <h2 class="section-title">1. Executive Summary</h2>
        <div class="executive-summary">
            <p>
                This report contains the results of an automated OSINT reconnaissance operation
                conducted via the LeakRecon framework. All network traffic was routed exclusively
                through the Tor anonymity network.
            </p>
            <p>
                <strong>Assessment Period:</strong> {generated}<br>
                <strong>Total Scans Executed:</strong> {len(scans)}<br>
                <strong>Unique Targets:</strong> {len(unique_targets)}<br>
                <strong>Total Findings:</strong> {total_findings}<br>
                <strong>Overall Risk Level:</strong>
                <span class="risk-badge" style="background: {risk_color};">{risk_level}</span>
            </p>
            <p><strong>Targets Assessed:</strong></p>
            <ul class="target-list">
                {''.join(f'<li>{_escape(t)}</li>' for t in unique_targets[:20])}
            </ul>
        </div>

        <!-- SECTION 2: FINDINGS OVERVIEW -->
        <h2 class="section-title">2. Findings Overview</h2>
        <div class="overview">
            <div class="overview-card">
                <div class="number">{stats['total_scans']}</div>
                <div class="label">Total Scans (All Time)</div>
            </div>
            <div class="overview-card">
                <div class="number">{total_findings}</div>
                <div class="label">Findings (This Report)</div>
            </div>
            <div class="overview-card">
                <div class="number">{total_clean}</div>
                <div class="label">Clean Results</div>
            </div>
            <div class="overview-card">
                <div class="number">{total_errors}</div>
                <div class="label">Errors / Unreachable</div>
            </div>
        </div>

        <!-- SECTION 3: TECHNICAL DETAILS -->
        <h2 class="section-title">3. Technical Details</h2>
        {''.join(scan_blocks)}

        <div class="footer">
            LeakRecon &middot; Dark Web Leak Intelligence Framework<br>
            This report was generated automatically. All traffic routed via Tor network. &middot; {generated}<br>
            Classification: CONFIDENTIAL &mdash; Handle according to organizational data handling policies.
        </div>
    </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path


def export_pdf(scan_ids: Optional[List[int]] = None) -> str:
    """
    Generates an enterprise PDF report by converting the HTML report via wkhtmltopdf.
    
    Args:
        scan_ids (Optional[List[int]]): Specific scan IDs to include. Includes all if None.
        
    Returns:
        str: The absolute path to the generated PDF file.
        
    Raises:
        ImportError: If the pdfkit library is not installed.
        OSError: If the wkhtmltopdf binary is not found on the system.
    """
    _ensure_dir()
    try:
        import pdfkit
    except ImportError:
        raise ImportError(
            "PDF generation requires the 'pdfkit' library. "
            "Install via 'pip install pdfkit'. "
            "Additionally, 'wkhtmltopdf' must be installed on the system."
        )

    html_path = export_html(scan_ids)
    fname = f"leakrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(REPORT_DIR, fname)

    options = {
        'page-size': 'A4',
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'encoding': "UTF-8",
        'enable-local-file-access': None,
        'no-outline': None,
        'print-media-type': None,
    }

    try:
        pdfkit.from_file(html_path, path, options=options)
    except OSError as e:
        if "No wkhtmltopdf executable found" in str(e):
            raise OSError(
                "wkhtmltopdf is not installed on this system. "
                "Download from: https://wkhtmltopdf.org/downloads.html"
            )
        raise e

    return path


def _escape(text: str) -> str:
    """
    Escapes HTML special characters for safe rendering.
    
    Args:
        text (str): Raw text to escape.
        
    Returns:
        str: HTML-safe escaped string.
    """
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("[link] ", "")
    )
