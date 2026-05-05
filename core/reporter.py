import os
import csv
import json
from datetime import datetime
from core import database as db

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


def _ensure_dir():
    os.makedirs(REPORT_DIR, exist_ok=True)


def export_json(scan_ids: list[int] | None = None) -> str:
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


def export_csv(scan_ids: list[int] | None = None) -> str:
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
            "Tarama ID", "Hedef", "Kategori", "Tarih", "Süre (sn)",
            "Kaynak", "Durum", "Eşleşmeler", "Hata",
        ])

        for scan_data in scans:
            scan = scan_data["scan"]
            for r in scan_data["results"]:
                status = "BULUNDU" if r["found"] else ("HATA" if r["error"] else "TEMİZ")
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


def export_html(scan_ids: list[int] | None = None) -> str:
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

    scan_blocks = []
    for scan_data in scans:
        scan = scan_data["scan"]
        rows = []
        for idx, r in enumerate(scan_data["results"], 1):
            if r["found"]:
                status_class = "status-found"
                status_text = "● BULUNDU"
            elif r["error"] and "Atlandı" in (r["error"] or ""):
                status_class = "status-skipped"
                status_text = "● ERİŞİLEMEDİ"
            elif r["error"]:
                status_class = "status-error"
                status_text = "● HATA"
            else:
                status_class = "status-clean"
                status_text = "● TEMİZ"

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
                detail = "Eşleşme bulunamadı"

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
                <h2>🔍 {_escape(scan['category'])}</h2>
                <span class="scan-time">{_escape(scan['timestamp'])}</span>
            </div>
            <div class="scan-meta">
                <div class="meta-item"><span class="label">Hedef</span><span class="value">{_escape(scan['target'])}</span></div>
                <div class="meta-item"><span class="label">Süre</span><span class="value">{scan['duration']:.1f}s</span></div>
                <div class="meta-item"><span class="label">Kaynak</span><span class="value">{scan['source_count']}</span></div>
                <div class="meta-item"><span class="label">Sorgu</span><span class="value">{scan['query_count']}</span></div>
            </div>
            <div class="scan-stats">
                <span class="stat stat-found">Tespit: {scan['found_count']}</span>
                <span class="stat stat-clean">Temiz: {scan['clean_count']}</span>
                <span class="stat stat-error">Hata: {scan['error_count']}</span>
                <span class="stat stat-skipped">Atlandı: {scan['skipped_count']}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th class="center" style="width:40px">#</th>
                        <th style="width:160px">Kaynak</th>
                        <th class="center" style="width:120px">Durum</th>
                        <th>Detay</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>""")

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LeakRecon — İstihbarat Raporu</title>
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
        .scan-header h2 {{ font-size: 1.1em; color: #e2e8f0; }}
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
            .scan-block {{ border-color: #ddd; }}
            .header h1 {{ color: #1a1a1a; -webkit-text-fill-color: #1a1a1a; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LEAKRECON</h1>
            <div class="subtitle">Dark Web Leak Intelligence — İstihbarat Raporu</div>
            <div class="generated">Oluşturulma: {generated}</div>
        </div>

        <div class="overview">
            <div class="overview-card">
                <div class="number">{stats['total_scans']}</div>
                <div class="label">Toplam Tarama</div>
            </div>
            <div class="overview-card">
                <div class="number">{stats['total_findings']}</div>
                <div class="label">Toplam Tespit</div>
            </div>
            <div class="overview-card">
                <div class="number">{stats['unique_targets']}</div>
                <div class="label">Benzersiz Hedef</div>
            </div>
            <div class="overview-card">
                <div class="number">{len(scans)}</div>
                <div class="label">Bu Rapordaki Tarama</div>
            </div>
        </div>

        {''.join(scan_blocks)}

        <div class="footer">
            LeakRecon · Dark Web Leak Intelligence Framework<br>
            Bu rapor otomatik olarak oluşturulmuştur · Gizlilik: TÜM trafik Tor ağı üzerinden · {generated}
        </div>
    </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path


def _escape(text: str) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("[link] ", "🔗 ")
    )
