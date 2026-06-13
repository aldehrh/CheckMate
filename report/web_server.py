"""
report/web_server.py
Flask 웹서버 — 점검 결과를 브라우저에서 바로 확인
"""

import webbrowser, threading
from flask import Flask, render_template_string
from checkers.base import ServiceReport, HIGH, MEDIUM, PASS, FAIL, WARN

# ── 색상 매핑 ─────────────────────────────────────
SVC_COLOR    = {"RDS":"#4f46e5","S3":"#0891b2","IAM":"#ea580c","EC2":"#16a34a",
                "CloudTrail":"#7c3aed","CloudWatch":"#db2777","VPC":"#0d9488"}
STATUS_COLOR = {PASS:"#16a34a", FAIL:"#dc2626", WARN:"#d97706"}
STATUS_ICON  = {PASS:"✓", FAIL:"✕", WARN:"⚠"}
SEV_COLOR    = {HIGH:"#dc2626", MEDIUM:"#d97706", "LOW":"#16a34a"}


def _score_grade(score):
    if score >= 90: return "A","#16a34a"
    if score >= 75: return "B","#65a30d"
    if score >= 60: return "C","#d97706"
    if score >= 40: return "D","#ea580c"
    return "F","#dc2626"


def _build_html(reports: list[ServiceReport]) -> str:
    all_results = [r for rpt in reports for r in rpt.results]
    
    # 카운트 계산 버그 교정
    total_f = sum(rpt.fail_count for rpt in reports)
    total_w = sum(rpt.warn_count for rpt in reports)
    total_p = sum(rpt.pass_count for rpt in reports)
    
    avg_score = int(sum(rpt.score for rpt in reports) / len(reports)) if reports else 0
    grade, gc = _score_grade(avg_score)

    # 서비스 카드 생성
    cards_html = ""
    for rpt in reports:
        sc, scc = _score_grade(rpt.score)
        col = SVC_COLOR.get(rpt.service, "#475569")
        bar = int(rpt.score)
        cards_html += f"""
        <div class="card">
          <div class="card-top" style="border-left:4px solid {col}">
            <span class="card-svc">{rpt.service}</span>
            <span class="card-grade" style="color:{scc}">{sc}</span>
          </div>
          <div class="bar-wrap"><div class="bar" style="width:{bar}%;background:linear-gradient(90deg,{scc},{col})"></div></div>
          <div class="card-stats">
            <span style="color:#16a34a; font-weight:600;">✓ {rpt.pass_count}</span>
            <span style="color:#d97706; font-weight:600;">⚠ {rpt.warn_count}</span>
            <span style="color:#dc2626; font-weight:600;">✕ {rpt.fail_count}</span>
            <span class="muted" style="margin-left:auto">{len(rpt.results)}개 항목</span>
          </div>
          <div class="score-lbl">{rpt.score}점</div>
        </div>"""

    # 결과 테이블 행 생성
    rows_html = ""
    for r in all_results:
        sc  = STATUS_COLOR.get(r.status,"#64748b")
        si  = STATUS_ICON.get(r.status, r.status)
        svc = SVC_COLOR.get(r.service,"#475569")
        sev = SEV_COLOR.get(r.severity,"#64748b")
        rem = f'<div class="rem"><code>{r.remediation}</code></div>' if r.status != PASS else ""
        rows_html += f"""
        <tr data-svc="{r.service}" data-status="{r.status}">
          <td><span class="badge" style="background:{svc}">{r.service}</span></td>
          <td class="mono">{r.check_id}</td>
          <td style="font-weight:600; color:#1e293b;">{r.name}</td>
          <td><span class="badge" style="background:{sev}">{r.severity}</span></td>
          <td><span class="dot" style="background:{sc}">{si}</span> <span style="font-weight:600; color:{sc};">{r.status}</span></td>
          <td class="mono small">{r.resource_id}</td>
          <td>
            <div style="color:#334155; margin-bottom:4px;">{r.detail}</div>
            {rem}
          </td>
        </tr>"""

    # 서비스 필터 버튼 중복 생성 방지
    unique_services = sorted(list(set(rpt.service for rpt in reports)))
    svc_btns = "".join(
        f'<button class="fbtn svc-btn" onclick="fSvc(\'{svc}\', this)">{svc}</button>'
        for svc in unique_services
    )

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS 보안 점검 결과 대시보드</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Noto+Sans+KR:wght@300;400;500;700&display=swap');

/* 밝은 라이트 모드 변수 선언 */
:root{{
  --bg: #f8fafc;
  --sur: #ffffff;
  --bdr: #e2e8f0;
  --txt: #0f172a;
  --muted: #64748b;
  --accent: #4f46e5;
}}

*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--txt);font-family:'Noto Sans KR',sans-serif;font-size:14px;line-height:1.6;}}

/* 헤더 - 밝고 세련된 그라데이션 */
.hdr{{background:linear-gradient(135deg,#f1f5f9,#e2e8f0 50%,#f1f5f9);border-bottom:1px solid var(--bdr);padding:36px 48px 28px;}}
.hdr-row{{display:flex;justify-content:space-between;align-items:flex-start;}}
.hdr-title{{font-size:26px;font-weight:700;color:var(--txt);}}
.hdr-title span{{color:var(--accent);}}
.hdr-meta{{font-size:12px;color:var(--muted);text-align:right;line-height:2;font-weight: 500;}}
.overall{{display:flex;align-items:center;gap:24px;margin-top:24px;background:var(--sur);border:1px solid var(--bdr);border-radius:12px;padding:18px 24px;box-shadow: 0 1px 3px rgba(0,0,0,0.05);}}
.grade-ring{{width:68px;height:68px;border-radius:50%;border:4px solid {gc};display:flex;flex-direction:column;align-items:center;justify-content:center;background:var(--sur);}}
.grade-letter{{font-size:30px;font-weight:700;color:{gc};line-height:1;}}
.grade-sub{{font-size:11px;color:var(--muted);font-weight:600;}}
.ov-txt h2{{font-size:18px;font-weight:700;}}
.ov-txt p{{font-size:13px;color:var(--muted);margin-top:3px;font-weight:500;}}
.pills{{display:flex;gap:10px;margin-top:10px;}}
.pill{{padding:4px 14px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid;}}
.p-pass{{color:#16a34a;border-color:rgba(22,163,74,.4);background:rgba(22,163,74,.08);}}
.p-warn{{color:#d97706;border-color:rgba(217,119,6,.4);background:rgba(217,119,6,.08);}}
.p-fail{{color:#dc2626;border-color:rgba(220,38,38,.4);background:rgba(220,38,38,.08);}}

/* 섹션 타이틀 */
.sec{{padding:28px 48px 14px;}}
.sec-title{{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;}}

/* 카드 컴포넌트 */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;}}
.card{{background:var(--sur);border:1px solid var(--bdr);border-radius:12px;padding:20px;box-shadow: 0 1px 3px rgba(0,0,0,0.02);transition:all .2s;}}
.card:hover{{transform:translateY(-3px);box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);}}
.card-top{{display:flex;justify-content:space-between;align-items:center;padding-left:10px;margin-bottom:12px;}}
.card-svc{{font-weight:700;font-size:16px;color:#1e293b;}}
.card-grade{{font-size:26px;font-weight:700;}}
.bar-wrap{{background:#e2e8f0;border-radius:999px;height:6px;overflow:hidden;margin-bottom:12px;}}
.bar{{height:100%;border-radius:999px;}}
.card-stats{{display:flex;gap:10px;font-size:12px; border-top: 1px solid #f1f5f9; padding-top: 10px;}}
.score-lbl{{text-align:right;font-size:12px;color:var(--muted);margin-top:6px;font-weight:600;}}
.muted{{color:var(--muted);}}

/* 컨트롤러 및 필터 바 */
.fbar{{padding:20px 48px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;}}
.flbl{{font-size:12px;font-weight:700;color:var(--muted);margin-right:4px;}}
.fbtn{{padding:6px 14px;border-radius:8px;border:1px solid var(--bdr);background:var(--sur);color:var(--muted);cursor:pointer;font-size:12px;font-weight:500;font-family:inherit;transition:all .15s;}}
.fbtn:hover, .fbtn.on{{border-color:var(--accent);color:var(--accent);background:rgba(79,70,229,.08);font-weight:700;}}
.fsearch{{padding:6px 14px;border-radius:8px;border:1px solid var(--bdr);background:var(--sur);color:var(--txt);font-family:inherit;font-size:12px;outline:none;width:240px;margin-left:auto;box-shadow: inset 0 1px 2px rgba(0,0,0,0.02);}}
.fsearch:focus{{border-color:var(--accent); box-shadow: 0 0 0 1px var(--accent);}}

/* 결과 대형 데이터 테이블 */
.twrap{{padding:0 48px 48px;overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;background:var(--sur);border:1px solid var(--bdr);border-radius:12px;overflow:hidden;box-shadow: 0 1px 3px rgba(0,0,0,0.02);}}
thead tr{{background:#f1f5f9;}}
th{{padding:12px 14px;text-align:left;font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr);white-space:nowrap;}}
td{{padding:14px;border-bottom:1px solid var(--bdr);vertical-align:top;font-size:13px;color:#475569;}}
tr:hover td{{background:#f8fafc;}}
tr.hide{{display:none;}}
.badge{{display:inline-block;padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap;}}
.dot{{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:5px;font-size:10px;font-weight:700;color:#fff;margin-right:4px;}}
.mono{{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:#334155;}}
.small{{word-break:break-all;max-width:160px;}}

/* 조치 방법 코드 블록 */
.rem{{margin-top:8px;padding:10px 14px;background:#f8fafc;border-left:3px solid var(--accent);border-radius:0 8px 8px 0; border:1px solid var(--bdr); border-left-width:3px;}}
.rem code{{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#4338ca;word-break:break-all;font-weight:500;}}

/* 푸터 */
footer{{text-align:center;padding:24px;font-size:12px;color:var(--muted);border-top:1px solid var(--bdr);background:#f1f5f9;font-weight:500;}}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-row">
    <div>
      <div class="hdr-title">AWS <span>보안 점검</span> 결과</div>
      <div style="color:var(--muted);font-size:13px;margin-top:3px;font-weight:500;">AWS Security Assessment Dashboard</div>
    </div>
    <div class="hdr-meta">
      점검 서비스: {', '.join(unique_services)}<br>
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
      <p>{'⚠️ 즉시 조치 필요 항목이 발견되었습니다.' if total_f > 0 else '✅ 모든 점검 항목이 양호합니다.'}</p>
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
  <button class="fbtn svc-btn on" onclick="fSvc('ALL', this)">전체</button>
  {svc_btns}
  <span class="flbl" style="margin-left:12px">상태:</span>
  <button class="fbtn st-btn on" onclick="fStatus('ALL', this)">전체</button>
  <button class="fbtn st-btn" onclick="fStatus('FAIL', this)" style="color:#dc2626">FAIL</button>
  <button class="fbtn st-btn" onclick="fStatus('WARN', this)" style="color:#d97706">WARN</button>
  <button class="fbtn st-btn" onclick="fStatus('PASS', this)" style="color:#16a34a">PASS</button>
  <input class="fsearch" id="kw" placeholder="항목명·리소스 식별자 검색..." oninput="applyFilter()">
</div>

<div class="twrap">
  <div class="sec-title">상세 점검 결과</div>
  <table>
    <thead><tr>
      <th>서비스</th><th>ID</th><th>점검 항목</th><th>위험도</th>
      <th>상태</th><th>리소스 ID</th><th>상세 내용 / 조치 방법</th>
    </tr></thead>
    <tbody id="tbody">{rows_html}</tbody>
  </table>
</div>

<footer>AWS 보안 점검 도구 · 본 보고서는 자동 생성되었으므로 운영 환경 적용 전 단계별 검토를 권장합니다.</footer>

<script>
let curSvc='ALL', curStatus='ALL';

function applyFilter(){{
  const kw = document.getElementById('kw').value.toLowerCase();
  document.querySelectorAll('#tbody tr').forEach(tr=>{{
    const svc = tr.dataset.svc, st = tr.dataset.status, txt = tr.textContent.toLowerCase();
    const ok = (curSvc==='ALL'||svc===curSvc)&&(curStatus==='ALL'||st===curStatus)&&(!kw||txt.includes(kw));
    tr.classList.toggle('hide', !ok);
  }});
}}

// 필터링 버튼 토글 액션 활성화 보정
function fSvc(v, btn){{
  curSvc = v;
  document.querySelectorAll('.svc-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  applyFilter();
}}

function fStatus(v, btn){{
  curStatus = v;
  document.querySelectorAll('.st-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  applyFilter();
}}
</script>
</body></html>"""


def run_server(reports: list[ServiceReport], port: int = 5000):
    """Flask 서버 시작 후 브라우저 자동 오픈"""
    app  = Flask(__name__)
    html = _build_html(reports)

    @app.route("/")
    def index():
        return render_template_string(html) # 안전한 렌더링 헬퍼 우회 적용

    def open_browser():
        import time; time.sleep(0.8)
        webbrowser.open(f"http://localhost:{port}")

    threading.Thread(target=open_browser, daemon=True).start()

    print(f"\n  🌐 브라우저에서 결과를 확인하세요 → http://localhost:{port}")
    print(f"  종료하려면 Ctrl+C 를 누르세요\n")
    app.run(port=port, debug=False, use_reloader=False)