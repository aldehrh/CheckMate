"""
report/web_server.py
Flask 웹서버 — 점검 결과를 브라우저에서 바로 확인
"""

import webbrowser, threading
from flask import Flask, render_template_string
from checkers.base import ServiceReport, HIGH, MEDIUM, PASS, FAIL, WARN

# ── 색상 매핑 ─────────────────────────────────────
SVC_COLOR    = {"RDS":"#6366f1","S3":"#06b6d4","IAM":"#f97316","EC2":"#10b981",
                "CloudTrail":"#8b5cf6","CloudWatch":"#ec4899","VPC":"#14b8a6"}
STATUS_COLOR = {PASS:"#22c55e", FAIL:"#ef4444", WARN:"#f59e0b"}
STATUS_ICON  = {PASS:"✓", FAIL:"✕", WARN:"⚠"}
SEV_COLOR    = {HIGH:"#ef4444", MEDIUM:"#f59e0b", "LOW":"#22c55e"}


def _score_grade(score):
    if score >= 90: return "A","#22c55e"
    if score >= 75: return "B","#84cc16"
    if score >= 60: return "C","#f59e0b"
    if score >= 40: return "D","#f97316"
    return "F","#ef4444"


def _build_html(reports: list[ServiceReport]) -> str:
    all_results = [r for rpt in reports for r in rpt.results]
    total_f = sum(r.fail_count for r in reports)
    total_w = sum(r.warn_count for r in reports)
    total_p = sum(r.pass_count for r in reports)
    avg_score = int(sum(r.score for r in reports) / len(reports)) if reports else 0
    grade, gc = _score_grade(avg_score)

    # 서비스 카드
    cards_html = ""
    for rpt in reports:
        sc, scc = _score_grade(rpt.score)
        col = SVC_COLOR.get(rpt.service, "#64748b")
        bar = int(rpt.score)
        cards_html += f"""
        <div class="card">
          <div class="card-top" style="border-left:4px solid {col}">
            <span class="card-svc">{rpt.service}</span>
            <span class="card-grade" style="color:{scc}">{sc}</span>
          </div>
          <div class="bar-wrap"><div class="bar" style="width:{bar}%;background:linear-gradient(90deg,{scc},{col})"></div></div>
          <div class="card-stats">
            <span style="color:#22c55e">✓ {rpt.pass_count}</span>
            <span style="color:#f59e0b">⚠ {rpt.warn_count}</span>
            <span style="color:#ef4444">✕ {rpt.fail_count}</span>
            <span class="muted" style="margin-left:auto">{len(rpt.results)}개</span>
          </div>
          <div class="score-lbl">{rpt.score}점</div>
        </div>"""

    # 결과 테이블 행
    rows_html = ""
    for r in all_results:
        sc  = STATUS_COLOR.get(r.status,"#94a3b8")
        si  = STATUS_ICON.get(r.status, r.status)
        svc = SVC_COLOR.get(r.service,"#64748b")
        sev = SEV_COLOR.get(r.severity,"#94a3b8")
        rem = f'<div class="rem"><code>{r.remediation}</code></div>' if r.status != PASS else ""
        rows_html += f"""
        <tr data-svc="{r.service}" data-status="{r.status}">
          <td><span class="badge" style="background:{svc}">{r.service}</span></td>
          <td class="mono">{r.check_id}</td>
          <td>{r.name}</td>
          <td><span class="badge" style="background:{sev}">{r.severity}</span></td>
          <td><span class="dot" style="background:{sc}">{si}</span> {r.status}</td>
          <td class="mono small">{r.resource_id}</td>
          <td>{r.detail}{rem}</td>
        </tr>"""

    svc_btns = "".join(
        f'<button class="fbtn" onclick="fSvc(\'{r.service}\')">{r.service}</button>'
        for r in reports
    )

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS 보안 점검 결과</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Noto+Sans+KR:wght@300;400;600;700&display=swap');
:root{{--bg:#0a0e1a;--sur:#111827;--bdr:#1e293b;--txt:#e2e8f0;--muted:#64748b;--accent:#6366f1;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--txt);font-family:'Noto Sans KR',sans-serif;font-size:14px;line-height:1.6;}}

/* 헤더 */
.hdr{{background:linear-gradient(135deg,#0f172a,#1e1b4b 50%,#0f172a);border-bottom:1px solid var(--bdr);padding:36px 48px 28px;}}
.hdr-row{{display:flex;justify-content:space-between;align-items:flex-start;}}
.hdr-title{{font-size:26px;font-weight:700;}}
.hdr-title span{{color:var(--accent);}}
.hdr-meta{{font-size:12px;color:var(--muted);text-align:right;line-height:2;}}
.overall{{display:flex;align-items:center;gap:24px;margin-top:24px;background:rgba(255,255,255,.03);border:1px solid var(--bdr);border-radius:12px;padding:18px 24px;}}
.grade-ring{{width:68px;height:68px;border-radius:50%;border:3px solid {gc};display:flex;flex-direction:column;align-items:center;justify-content:center;}}
.grade-letter{{font-size:30px;font-weight:700;color:{gc};line-height:1;}}
.grade-sub{{font-size:11px;color:var(--muted);}}
.ov-txt h2{{font-size:18px;font-weight:600;}}
.ov-txt p{{font-size:13px;color:var(--muted);margin-top:3px;}}
.pills{{display:flex;gap:10px;margin-top:10px;}}
.pill{{padding:3px 12px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid;}}
.p-pass{{color:#22c55e;border-color:rgba(34,197,94,.4);background:rgba(34,197,94,.1);}}
.p-warn{{color:#f59e0b;border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.1);}}
.p-fail{{color:#ef4444;border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.1);}}

/* 섹션 */
.sec{{padding:28px 48px;}}
.sec-title{{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;}}

/* 카드 */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;}}
.card{{background:var(--sur);border:1px solid var(--bdr);border-radius:12px;padding:18px;transition:transform .2s;}}
.card:hover{{transform:translateY(-2px);}}
.card-top{{display:flex;justify-content:space-between;align-items:center;padding-left:10px;margin-bottom:12px;}}
.card-svc{{font-weight:700;font-size:15px;}}
.card-grade{{font-size:26px;font-weight:700;}}
.bar-wrap{{background:#1e293b;border-radius:999px;height:5px;overflow:hidden;margin-bottom:10px;}}
.bar{{height:100%;border-radius:999px;}}
.card-stats{{display:flex;gap:8px;font-size:12px;}}
.score-lbl{{text-align:right;font-size:12px;color:var(--muted);margin-top:4px;}}
.muted{{color:var(--muted);}}

/* 필터 */
.fbar{{padding:0 48px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;}}
.flbl{{font-size:12px;color:var(--muted);}}
.fbtn{{padding:5px 14px;border-radius:8px;border:1px solid var(--bdr);background:var(--sur);color:var(--muted);cursor:pointer;font-size:12px;font-family:inherit;transition:all .15s;}}
.fbtn:hover,.fbtn.on{{border-color:var(--accent);color:var(--txt);background:rgba(99,102,241,.12);}}
.fsearch{{padding:5px 12px;border-radius:8px;border:1px solid var(--bdr);background:var(--sur);color:var(--txt);font-family:inherit;font-size:12px;outline:none;width:200px;margin-left:auto;}}
.fsearch:focus{{border-color:var(--accent);}}

/* 테이블 */
.twrap{{padding:0 48px 48px;overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;}}
thead tr{{background:#0f172a;}}
th{{padding:9px 12px;text-align:left;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr);white-space:nowrap;}}
td{{padding:9px 12px;border-bottom:1px solid rgba(30,41,59,.5);vertical-align:top;}}
tr:hover td{{background:rgba(255,255,255,.02);}}
tr.hide{{display:none;}}
.badge{{display:inline-block;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap;}}
.dot{{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:4px;font-size:10px;font-weight:700;color:#fff;margin-right:3px;}}
.mono{{font-family:'IBM Plex Mono',monospace;font-size:12px;}}
.small{{font-size:12px;word-break:break-all;max-width:140px;}}
.rem{{margin-top:7px;padding:7px 10px;background:rgba(99,102,241,.08);border-left:3px solid var(--accent);border-radius:0 6px 6px 0;}}
.rem code{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:#a5b4fc;word-break:break-all;}}

/* 푸터 */
footer{{text-align:center;padding:20px;font-size:12px;color:var(--muted);border-top:1px solid var(--bdr);}}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-row">
    <div>
      <div class="hdr-title">AWS <span>보안 점검</span> 결과</div>
      <div style="color:var(--muted);font-size:13px;margin-top:3px">AWS Security Assessment Dashboard</div>
    </div>
    <div class="hdr-meta">
      점검 서비스: {', '.join(r.service for r in reports)}<br>
      총 점검 항목: {len(all_results)}개
    </div>
  </div>
  <div class="overall">
    <div class="grade-ring">
      <div class="grade-letter">{grade}</div>
      <div class="grade-sub">{avg_score}점</div>
    </div>
    <div class="ov-txt">
      <h2>종합 보안 등급 <span style="color:{gc}">{grade}등급</span></h2>
      <p>{'즉시 조치 필요 항목이 있습니다' if total_f > 0 else '전체 점검 항목 양호'}</p>
      <div class="pills">
        <span class="pill p-pass">✓ PASS {total_p}</span>
        <span class="pill p-warn">⚠ WARN {total_w}</span>
        <span class="pill p-fail">✕ FAIL {total_f}</span>
      </div>
    </div>
  </div>
</div>

<div class="sec">
  <div class="sec-title">서비스별 보안 점수</div>
  <div class="cards">{cards_html}</div>
</div>

<div class="fbar">
  <span class="flbl">서비스:</span>
  <button class="fbtn on" onclick="fSvc('ALL')">전체</button>
  {svc_btns}
  <span class="flbl" style="margin-left:8px">상태:</span>
  <button class="fbtn on" onclick="fStatus('ALL')">전체</button>
  <button class="fbtn" onclick="fStatus('FAIL')" style="color:#ef4444">FAIL</button>
  <button class="fbtn" onclick="fStatus('WARN')" style="color:#f59e0b">WARN</button>
  <button class="fbtn" onclick="fStatus('PASS')" style="color:#22c55e">PASS</button>
  <input class="fsearch" id="kw" placeholder="항목명·리소스 검색..." oninput="applyFilter()">
</div>

<div class="twrap">
  <div class="sec-title">상세 점검 결과</div>
  <table>
    <thead><tr>
      <th>서비스</th><th>ID</th><th>점검 항목</th><th>위험도</th>
      <th>상태</th><th>리소스</th><th>상세 내용 / 조치 방법</th>
    </tr></thead>
    <tbody id="tbody">{rows_html}</tbody>
  </table>
</div>

<footer>AWS 보안 점검 도구 · 자동 생성된 결과로, 실제 운영 환경 적용 전 전문가 검토를 권장합니다.</footer>

<script>
let curSvc='ALL', curStatus='ALL';
function applyFilter(){{
  const kw=document.getElementById('kw').value.toLowerCase();
  document.querySelectorAll('#tbody tr').forEach(tr=>{{
    const svc=tr.dataset.svc, st=tr.dataset.status, txt=tr.textContent.toLowerCase();
    const ok=(curSvc==='ALL'||svc===curSvc)&&(curStatus==='ALL'||st===curStatus)&&(!kw||txt.includes(kw));
    tr.classList.toggle('hide',!ok);
  }});
}}
function fSvc(v){{curSvc=v;applyFilter();}}
function fStatus(v){{curStatus=v;applyFilter();}}
</script>
</body></html>"""


def run_server(reports: list[ServiceReport], port: int = 5000):
    """Flask 서버 시작 후 브라우저 자동 오픈"""
    app  = Flask(__name__)
    html = _build_html(reports)

    @app.route("/")
    def index():
        return html

    # 브라우저 자동 오픈 (서버 준비 후 0.8초 딜레이)
    def open_browser():
        import time; time.sleep(0.8)
        webbrowser.open(f"http://localhost:{port}")

    threading.Thread(target=open_browser, daemon=True).start()

    print(f"\n  🌐 브라우저에서 결과를 확인하세요 → http://localhost:{port}")
    print(f"  종료하려면 Ctrl+C 를 누르세요\n")
    app.run(port=port, debug=False, use_reloader=False)
