const logList = document.getElementById('log-list');
const siteList = document.getElementById('site-list');
const filterInput = document.getElementById('filter-input');
const sidebarFilter = document.getElementById('sidebar-filter');
const replayModal = document.getElementById('replay-modal');
const editPayload = document.getElementById('edit-payload');
const editHeaders = document.getElementById('edit-headers');

let allLogs = [];
let currentDomain = 'all';
let pendingLog = null;
const domains = new Set(['all']);

const SECURITY_RULES = [
    { name: "주민등록번호", regex: /\d{2}([0]\d|[1][0-2])([0][1-9]|[1-2]\d|[3][0-1])[-]*[1-4]\d{6}/g },
    { name: "API Key (Generic)", regex: /([^a-z0-9])(key|api|token|secret|auth)([\s"':]+)([a-z0-9\-_{}]{16,})/gi },
    { name: "JWT Token", regex: /ey[a-zA-Z0-9-_=]+\.ey[a-zA-Z0-9-_=]+\.?[a-zA-Z0-9-_.+/=]*/g },
    { name: "AWS Key", regex: /AKIA[0-9A-Z]{16}/g },
    { name: "Email 노출", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
    { name: "Firebase URL", regex: /[a-z0-9.-]+\.firebaseio\.com/gi }
];

function scanSecurityRisks(data) {
    if (typeof data !== 'string') data = JSON.stringify(data);
    const findings = [];
    SECURITY_RULES.forEach(rule => {
        const matches = data.match(rule.regex);
        if (matches) findings.push(`${rule.name} (${matches.length}건)`);
    });
    return findings;
}

function getLatencyClass(ms) {
    if (ms < 300) return 'fast';
    if (ms < 1000) return 'medium';
    return 'slow';
}

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.onclick = () => {
        document.querySelectorAll('.tab-btn, .tab-pane').forEach(el => el.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
    };
});

function renderHexView(data) {
    const display = document.getElementById('hex-display');
    if (!data || data === "데이터 없음") return display.textContent = "데이터가 없습니다.";
    const bytes = new TextEncoder().encode(data);
    let output = "OFFSET    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII\n--------------------------------------------------------------------------\n";
    for (let i = 0; i < bytes.length; i += 16) {
        output += i.toString(16).padStart(8, '0').toUpperCase() + "  ";
        let hex = ""; let ascii = "";
        for (let j = 0; j < 16; j++) {
            if (i + j < bytes.length) {
                const b = bytes[i + j];
                hex += b.toString(16).padStart(2, '0').toUpperCase() + " ";
                ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
            } else { hex += "   "; }
        }
        output += hex + "  " + ascii + "\n";
        if (i > 8000) { output += "\n[데이터가 너무 커서 중략되었습니다]"; break; }
    }
    display.textContent = output;
}

function renderLog(log) {
    if (!log.status || log.status.startsWith('0')) return;

    if (!domains.has(log.domain)) {
        domains.add(log.domain);
        const div = document.createElement('div');
        div.className = 'site-item'; div.dataset.domain = log.domain; div.textContent = log.domain;
        siteList.appendChild(div);
    }

    const risks = scanSecurityRisks(log.sent + log.received);
    const hasRisk = risks.length > 0;
    const lClass = getLatencyClass(log.latency);

    const item = document.createElement('div');
    item.className = `log-item ${hasRisk ? 'has-security-issue' : ''}`;
    item.setAttribute('data-domain', log.domain);
    item.setAttribute('data-url', log.url);
    
    const statusVal = parseInt(log.status);
    const statusClass = (statusVal >= 200 && statusVal < 300) ? 'status-200' : 'status-error';

    item.innerHTML = `
        <div class="url-row">
            <div class="url-info">
                <span class="method-tag">${log.method}</span>
                <span style="font-size:12px; color:#aaa; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:300px;">${log.url}</span>
                <span class="status-badge ${statusClass}">${log.status}</span>
                ${hasRisk ? `<span class="security-badge">⚠️ RISK DETECTED</span>` : ''}
            </div>
            <button class="replay-btn">REPLAY</button>
        </div>
        
        <div class="latency-info">
            <span style="color:#888;">Response Time:</span> 
            <span class="${lClass}">${log.latency}ms</span>
        </div>

        <div class="security-alert-box" style="${hasRisk ? 'display:block' : ''}">
            <strong>[보안 경고]</strong> 다음 정보가 감지되었습니다: ${risks.join(', ')}
        </div>
        <span class="data-label label-sent">▼ 보낸 데이터</span>
        <div class="content-box">${escapeHtml(formatJSON(log.sent))}</div>
        <span class="data-label label-recv">▼ 받은 데이터</span>
        <div class="content-box res-content">${escapeHtml(formatJSON(log.received))}</div>
    `;

    item.querySelector('.replay-btn').onclick = () => {
        pendingLog = log;
        editPayload.value = formatJSON(log.sent);
        editHeaders.value = JSON.stringify(log.reqHeaders || {"Content-Type":"application/json"}, null, 2);
        
        document.getElementById('diff-original').textContent = formatJSON(log.received);
        document.getElementById('diff-modified').textContent = "실행 대기 중...";
        
        renderHexView(log.received);
        replayModal.style.display = 'flex';
    };
    
    logList.prepend(item);
    refreshDisplay();
    return item;
}

document.getElementById('modal-send').onclick = () => {
    const bodyRaw = editPayload.value;
    let headersObj = {};
    try { headersObj = JSON.parse(editHeaders.value); } catch(e) { alert("Header 형식이 잘못되었습니다."); return; }
    
    document.querySelector('[data-tab="tab-diff"]').click();
    document.getElementById('diff-modified').textContent = "실행 중 (Loading)...";

    const fetchCode = `
        (async () => {
            try {
                const res = await fetch("${pendingLog.url}", {
                    method: "${pendingLog.method}",
                    headers: ${JSON.stringify(headersObj)},
                    body: ${pendingLog.method !== 'GET' ? '`' + bodyRaw.replace(/`/g, '\\`').replace(/\\/g, '\\\\') + '`' : 'null'},
                    credentials: 'include'
                });
                return { status: res.status, st: res.statusText, data: await res.text() };
            } catch (e) { return { error: e.message }; }
        })()
    `;

    chrome.devtools.inspectedWindow.eval(fetchCode, (result) => {
        const responseData = result.error || result.data;
        document.getElementById('diff-modified').textContent = formatJSON(responseData);

        const replayLog = {
            domain: pendingLog.domain, url: `[REPLAY] ${pendingLog.url}`,
            method: pendingLog.method, sent: bodyRaw, received: responseData,
            status: result.status ? `${result.status} ${result.st}` : "ERR",
            latency: 0,
            reqHeaders: headersObj
        };
        allLogs.push(replayLog);
        renderLog(replayLog);
    });
};

chrome.devtools.network.onRequestFinished.addListener((request) => {
    const url = request.request.url;
    let domain = "unknown";
    try { domain = new URL(url).hostname; } catch(e) {}
    
    const logObj = {
        domain, url, method: request.request.method,
        sent: request.request.postData ? request.request.postData.text : "None",
        received: "Loading...", 
        status: `${request.response.status} ${request.response.statusText}`,
        latency: Math.round(request.time),
        reqHeaders: request.request.headers.reduce((acc, h) => (acc[h.name] = h.value, acc), {})
    };
    
    const element = renderLog(logObj);
    request.getContent((c) => {
        logObj.received = c || "데이터 없음";
        allLogs.push(logObj);
        const risks = scanSecurityRisks(logObj.sent + logObj.received);
        if (risks.length > 0) {
            element.classList.add('has-security-issue');
            const alertBox = element.querySelector('.security-alert-box');
            alertBox.style.display = 'block';
            alertBox.innerHTML = `<strong>[보안 경고]</strong> 다음 정보가 감지되었습니다: ${risks.join(', ')}`;
        }
        const resBox = element.querySelector('.res-content');
        if (resBox) resBox.innerHTML = escapeHtml(formatJSON(logObj.received));
    });
});

function refreshDisplay() {
    const term = filterInput.value.toLowerCase();
    logList.querySelectorAll('.log-item').forEach(item => {
        const url = item.getAttribute('data-url').toLowerCase();
        const domain = item.getAttribute('data-domain');
        const isMatch = (currentDomain === 'all' || domain === currentDomain) && url.includes(term);
        item.style.display = isMatch ? 'flex' : 'none';
    });
}

function generateReport() {
    if (allLogs.length === 0) { alert("리포트를 생성할 로그가 없습니다."); return; }

    const securityLogs = allLogs.filter(log => scanSecurityRisks(log.sent + log.received).length > 0);
    const domainStats = [...domains].filter(d => d !== 'all').map(d => ({
        name: d,
        count: allLogs.filter(l => l.domain === d).length,
        risks: allLogs.filter(l => l.domain === d && scanSecurityRisks(l.sent + l.received).length > 0).length
    }));

    const reportHtml = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Hunter Analysis Report</title>
        <style>
            body { font-family: sans-serif; padding: 40px; background: #f4f7f9; color: #333; }
            .container { max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            h1 { color: #007bff; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
            .summary-cards { display: flex; gap: 20px; margin: 30px 0; }
            .card { flex: 1; padding: 20px; border-radius: 8px; text-align: center; color: white; }
            .card.blue { background: #007bff; }
            .card.red { background: #dc3545; }
            .card.green { background: #28a745; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
            th { background: #f8f9fa; }
            .risk-row { background: #fff5f5; color: #c53030; font-weight: bold; }
            .code-box { background: #2d2d2d; color: #ccc; padding: 10px; border-radius: 4px; font-size: 12px; white-space: pre-wrap; word-break: break-all; margin-top: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Security Hunter 분석 리포트</h1>
            <p>생성 일시: ${new Date().toLocaleString()}</p>
            
            <div class="summary-cards">
                <div class="card blue"><h3>총 요청</h3><p>${allLogs.length}건</p></div>
                <div class="card red"><h3>보안 위협</h3><p>${securityLogs.length}건</p></div>
                <div class="card green"><h3>분석 도메인</h3><p>${domains.size - 1}개</p></div>
            </div>

            <h2>1. 도메인별 요약</h2>
            <table>
                <thead><tr><th>도메인</th><th>전체 요청</th><th>보안 위협 발견</th></tr></thead>
                <tbody>
                    ${domainStats.map(s => `<tr><td>${s.name}</td><td>${s.count}</td><td>${s.risks}</td></tr>`).join('')}
                </tbody>
            </table>

            <h2>2. 상세 보안 위협 내역 (Top 50)</h2>
            ${securityLogs.slice(0, 50).map(log => `
                <div style="margin-bottom: 30px; border-left: 5px solid #dc3545; padding-left: 15px;">
                    <div style="font-weight: bold; font-size: 1.1em;">[${log.method}] ${log.url}</div>
                    <div style="color: #dc3545; margin: 5px 0;">검출항목: ${scanSecurityRisks(log.sent + log.received).join(', ')}</div>
                    <div class="code-box">${escapeHtml(log.received.substring(0, 500))}...</div>
                </div>
            `).join('')}
        </div>
    </body>
    </html>`;

    const blob = new Blob([reportHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Security_Report_${new Date().getTime()}.html`;
    a.click();
}

// 사이드바 검색창 입력 시 실행되는 로직
sidebarFilter.oninput = () => {
    const searchTerm = sidebarFilter.value.toLowerCase(); // 입력한 검색어
    const items = siteList.querySelectorAll('.site-item'); // 왼쪽 도메인 아이템들
    
    items.forEach(item => {
        const domainText = item.textContent.toLowerCase();
        if (item.dataset.domain === 'all') {
            item.style.display = 'block'; // '모든 기록'은 항상 표시
        } else {
            // 검색어가 포함된 도메인만 보여줌
            item.style.display = domainText.includes(searchTerm) ? 'block' : 'none';
        }
    });

    refreshDisplay(); // 검색 결과에 맞춰 오른쪽 로그 리스트도 같이 필터링
};
siteList.onclick = (e) => {
    const target = e.target.closest('.site-item');
    if (!target) return;
    siteList.querySelectorAll('.site-item').forEach(el => el.classList.remove('active'));
    target.classList.add('active');
    currentDomain = target.dataset.domain;
    refreshDisplay();
};
filterInput.oninput = refreshDisplay;
function formatJSON(d) { try { return JSON.stringify(JSON.parse(d), null, 2); } catch(e) { return d; } }
function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
document.getElementById('modal-cancel').onclick = () => replayModal.style.display = 'none';
document.getElementById('clear-btn').onclick = () => { logList.innerHTML = ''; allLogs = []; siteList.innerHTML = '<div class="site-item active" data-domain="all">모든 기록</div>'; domains.clear(); domains.add('all'); };
document.getElementById('download-btn').onclick = generateReport;



/* ----------------------------------------------------------------
   [추가 기능] 4. API 문서화 자동화 (Swagger/OpenAPI Spec 생성)
----------------------------------------------------------------- */

function generateSwagger() {
    if (allLogs.length === 0) { alert("문서를 생성할 데이터가 없습니다."); return; }

    const spec = {
        openapi: "3.0.0",
        info: {
            title: "Security Hunter Auto-Generated API Docs",
            version: "1.0.0",
            description: "수집된 네트워크 트래픽을 기반으로 자동 생성된 API 명세서입니다."
        },
        paths: {}
    };

    allLogs.forEach(log => {
        let pathName;
        try {
            pathName = new URL(log.url).pathname;
        } catch(e) {
            pathName = log.url;
        }

        if (!spec.paths[pathName]) spec.paths[pathName] = {};

        const method = log.method.toLowerCase();
        spec.paths[pathName][method] = {
            summary: `${pathName} 자동 분석 결과`,
            responses: {
                "200": {
                    description: "성공 응답",
                    content: { "application/json": { example: tryParse(log.received) } }
                }
            }
        };

        // 요청 바디가 있는 경우 (POST, PUT 등)
        if (log.sent && log.sent !== "None") {
            spec.paths[pathName][method].requestBody = {
                content: { "application/json": { example: tryParse(log.sent) } }
            };
        }
    });

    const blob = new Blob([JSON.stringify(spec, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `API_Spec_${new Date().getTime()}.json`;
    a.click();
}
// 아니 근데 진짜로 다시 생각해도 개빡 하ㅏ
function tryParse(data) {
    try { return JSON.parse(data); } catch(e) { return data; }
}

// Swagger 버튼 이벤트 바인딩
document.getElementById('swagger-btn').onclick = generateSwagger;

/* =================================================
   추가 기능(add fun)
   ================================================= */

(function () {
  /* ---------- Entropy ---------- */
  function __calcEntropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    return Object.values(freq).reduce((e, f) => {
      const p = f / str.length;
      return e - p * Math.log2(p);
    }, 0);
  }

  function __looksLikeSecret(str) {
    if (typeof str !== "string") return false;
    if (str.length < 20) return false;
    if (!/[A-Za-z]/.test(str) || !/[0-9]/.test(str)) return false;
    return __calcEntropy(str) >= 3.5;
  }

  /* ---------- Candidate Extract ---------- */
  function __extract(text) {
    const out = [];
    try {
      const json = JSON.parse(text);
      (function walk(v, path = "") {
        if (typeof v === "string") {
          out.push({ value: v, path });
        } else if (typeof v === "object" && v) {
          Object.entries(v).forEach(([k, val]) =>
            walk(val, path ? `${path}.${k}` : k)
          );
        }
      })(json);
    } catch {
      text.match(/[A-Za-z0-9_\-\.]{20,}/g)?.forEach(v =>
        out.push({ value: v, path: "raw" })
      );
    }
    return out;
  }

  /* ---------- Main Scan ---------- */
  function advancedSecurityScan(sent, received) {
    const findings = [];

    [
      { data: sent, isResponse: false },
      { data: received, isResponse: true }
    ].forEach(({ data, isResponse }) => {
      if (!data || typeof data !== "string") return;

      __extract(data).forEach(({ value, path }) => {
        let score = 0;

        // JWT
        if (/^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(value)) {
          findings.push({
            type: "JWT",
            score: 80,
            msg: `${isResponse ? "응답" : "요청"}에서 JWT 발견 (${path})`
          });
          return;
        }

        // High entropy secret
        if (__looksLikeSecret(value)) {
          score += 40;
          if (isResponse) score += 20;
          if (/auth|token|secret|key/i.test(path)) score += 30;
          if (/example|sample|test/i.test(path)) score -= 40;

          if (score >= 50) {
            findings.push({
              type: "Possible Secret",
              score,
              msg: `고엔트로피 값 발견 (${path})`
            });
          }
        }
      });
    });

    return findings;
  }

  /* ---------- Hook (기존 코드 무침범) ---------- */
  const _origGetContent = chrome.devtools.network.onRequestFinished.addListener;

  chrome.devtools.network.onRequestFinished.addListener = function (cb) {
    _origGetContent.call(chrome.devtools.network.onRequestFinished, function (request) {
      cb(request);

      request.getContent((body) => {
        try {
          const element = document.querySelector(
            `.log-item[data-url="${request.request.url}"]`
          );
          if (!element) return;

          const sent = request.request.postData?.text || "";
          const received = body || "";

          const adv = advancedSecurityScan(sent, received);
          if (adv.length === 0) return;

          const box = element.querySelector(".security-alert-box");
          if (!box) return;

          box.style.display = "block";
          box.innerHTML += `
            <br><strong>[정밀 분석]</strong><br>
            ${adv.map(v =>
              `• ${v.type} (${v.score}점): ${v.msg}`
            ).join("<br>")}
          `;
        } catch (e) {
          console.warn("Advanced scan error", e);
        }
      });
    });
  };
})();



/* ============================
   정밀 분석 (Low Risk 판단 레이어)
   기존 로직 수정 없음
============================ */

(function () {
  const ANALYZED_FLAG = 'data-precision-analyzed';

  function isKnownYoutubeClientToken(text) {
    if (!text) return false;

    return [
      /youtubei\/v1/i,
      /visitorData/i,
      /clientVersion/i,
      /INNERTUBE/i,
      /googlevideo\.com/i
    ].some(r => r.test(text));
  }

  function injectPrecisionAnalysis(card) {
    if (card.hasAttribute(ANALYZED_FLAG)) return;

    const text = card.innerText || '';
    if (!text.includes('API Key (Generic)')) return;

    // YouTube / Google 패턴만 Low Risk 처리
    if (!isKnownYoutubeClientToken(text)) return;

    card.setAttribute(ANALYZED_FLAG, 'true');

    const block = document.createElement('div');
    block.style.marginTop = '8px';
    block.style.paddingTop = '6px';
    block.style.borderTop = '1px dashed #aaa';
    block.style.fontSize = '12px';
    block.style.lineHeight = '1.5';

    block.innerHTML = `
      <strong>[정밀 분석]</strong><br>
      🟢 <strong>위험도 낮음</strong> (신뢰도 0.91)<br>
      - 이유: 알려진 YouTube client token 패턴<br>
      - 조치: 무시 가능
    `;

    card.appendChild(block);
  }

  // 동적으로 생성되는 요청 카드 감시
  const observer = new MutationObserver(() => {
    document
      .querySelectorAll('.request-item, .log-item, .network-entry')
      .forEach(injectPrecisionAnalysis);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
})();

/* =====================================================
   정밀 분석 엔진 v1
   - 기존 코드 수정 없음
   - 판단 / 신뢰도 / Provider 화이트리스트 포함
===================================================== */

(function () {
  const ANALYZED_FLAG = 'data-precision-analyzed';

  /* -------------------------------
     Provider 정의
  -------------------------------- */
  const PROVIDERS = [
    {
      name: 'YouTube',
      domains: ['youtube.com', 'googlevideo.com'],
      patterns: [/youtubei\/v1/i, /INNERTUBE/i, /visitorData/i],
      baseConfidence: 0.85
    },
    {
      name: 'Google',
      domains: ['google.com'],
      patterns: [/AIza[0-9A-Za-z\-_]{30,}/],
      baseConfidence: 0.75
    },
    {
      name: 'Naver',
      domains: ['naver.com'],
      patterns: [/client_secret/i, /X-Naver/i],
      baseConfidence: 0.6
    },
    {
      name: 'Kakao',
      domains: ['kakao.com'],
      patterns: [/KakaoAK/i],
      baseConfidence: 0.6
    }
  ];

  /* -------------------------------
     유틸
  -------------------------------- */
  function getCurrentHost() {
    return location.hostname || '';
  }

  function detectProvider(text) {
    const host = getCurrentHost();

    for (const p of PROVIDERS) {
      const domainMatch = p.domains.some(d => host.endsWith(d));
      const patternMatch = p.patterns.some(r => r.test(text));

      if (domainMatch && patternMatch) {
        return p;
      }
    }
    return null;
  }

  function isJWT(text) {
    return /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(text);
  }

  function calcEntropyScore(text) {
    if (!text || text.length < 20) return 0;
    let score = Math.min(text.length / 100, 1);
    if (/[A-Z]/.test(text)) score += 0.1;
    if (/[0-9]/.test(text)) score += 0.1;
    if (/[\-_]/.test(text)) score += 0.1;
    return Math.min(score, 1);
  }

  function clamp(num) {
    return Math.max(0, Math.min(1, num));
  }

  /* -------------------------------
     핵심 분석 로직
  -------------------------------- */
  function analyze(text) {
    let confidence = 0;
    let risk = 'low';
    let reason = '';
    let action = '';

    // 1. JWT는 무조건 고위험
    if (isJWT(text)) {
      return {
        risk: 'high',
        confidence: 0.95,
        reason: 'JWT 토큰 구조 감지',
        action: 'Authorization Header 사용 권장'
      };
    }

    // 2. Provider 기반 Low Risk 판단
    const provider = detectProvider(text);
    if (provider) {
      confidence += provider.baseConfidence;
      reason = `알려진 ${provider.name} 클라이언트 토큰 패턴`;
      action = '무시 가능 (정상 서비스 트래픽)';
      risk = 'low';
      return {
        risk,
        confidence: clamp(confidence),
        reason,
        action
      };
    }

    // 3. 기타 토큰 → 중간 위험
    const entropy = calcEntropyScore(text);
    if (entropy > 0.6) {
      return {
        risk: 'medium',
        confidence: clamp(0.5 + entropy / 2),
        reason: '고엔트로피 토큰 형태',
        action: '노출 여부 확인 필요'
      };
    }

    return {
        risk: 'unknown',
        confidence: 0.5,
         reason: '명확한 Provider 또는 고위험 패턴과 일치하지 않음',
          action: '수동 확인 권장'
    };

  }

  /* -------------------------------
     UI 삽입
  -------------------------------- */
  function injectAnalysis(card) {
    if (card.hasAttribute(ANALYZED_FLAG)) return;

    const text = card.innerText || '';
    if (!text.includes('API Key (Generic)')) return;

    const result = analyze(text);
    if (!result) return;

    card.setAttribute(ANALYZED_FLAG, 'true');

    let color = '⚪';
    if (result.risk === 'high') color = '🔴';
    else if (result.risk === 'medium') color = '🟡';
    else if (result.risk === 'low') color = '🟢';




    const block = document.createElement('div');
    block.style.marginTop = '8px';
    block.style.paddingTop = '6px';
    block.style.borderTop = '1px dashed #aaa';
    block.style.fontSize = '12px';
    block.style.lineHeight = '1.5';

    block.innerHTML = `
      <strong>[정밀 분석]</strong><br>
      ${color} <strong>위험도 ${result.risk}</strong>
      (신뢰도 ${result.confidence.toFixed(2)})<br>
      - 이유: ${result.reason}<br>
      - 조치: ${result.action}
    `;

    card.appendChild(block);
  }

  /* -------------------------------
     DOM 감시
  -------------------------------- */
  const observer = new MutationObserver(() => {
    document
      .querySelectorAll('.request-item, .log-item, .network-entry')
      .forEach(injectAnalysis);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

})();
