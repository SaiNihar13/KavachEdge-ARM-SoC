from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from stage1_detector import KavachStage1Detector
from stage2_advisor import KavachLlamaAdvisor

app = FastAPI(title="KavachEdge — Offline AI Security Assistant")
detector = KavachStage1Detector()
advisor = KavachLlamaAdvisor()

class TextScanRequest(BaseModel):
    content: str

class NetScanRequest(BaseModel):
    pps: float
    avg_bytes: float
    syn_ratio: float
    dst_ports: int
    external: int

@app.post("/api/scan/url")
def scan_url(req: TextScanRequest):
    det = detector.analyze_url(req.content)
    adv = advisor.generate_advisory(det)
    return {"detection": det, "advisory": adv}

@app.post("/api/scan/sms")
def scan_sms(req: TextScanRequest):
    det = detector.analyze_sms(req.content)
    adv = advisor.generate_advisory(det)
    return {"detection": det, "advisory": adv}

@app.post("/api/scan/network")
def scan_net(req: NetScanRequest):
    det = detector.analyze_network_flow(req.pps, req.avg_bytes, req.syn_ratio, req.dst_ports, req.external)
    adv = advisor.generate_advisory(det)
    return {"detection": det, "advisory": adv}

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
  <title>KavachEdge — On-Device AI Threat Detection</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; max-width: 960px; margin: 24px auto; padding: 0 16px; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 14px; }
    .badge { background: #065f46; color: #6ee7b7; padding: 6px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; }
    .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-top: 20px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; }
    textarea, input { width: 100%; box-sizing: border-box; background: #0f172a; color: #f8fafc; border: 1px solid #475569; border-radius: 6px; padding: 8px; margin: 8px 0; }
    button { background: #2563eb; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 6px; margin-top: 4px; }
    button.danger { background: #dc2626; }
    .result { margin-top: 22px; background: #1e293b; border-left: 5px solid #3b82f6; padding: 18px; border-radius: 8px; display: none; }
    .threat { border-left-color: #ef4444; }
    .safe { border-left-color: #10b981; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h2 style="margin:0;">🛡️ KavachEdge AI Security Assistant</h2>
      <small style="color:#94a3b8;">Llama 3.2 1B (INT8) + ExecuTorch Runtime | Zero-Cloud Edge Defense</small>
    </div>
    <span class="badge">● 100% OFFLINE LOCAL INFERENCE</span>
  </div>

  <div class="grid">
    <div class="card">
      <h3>1. Phishing URL Scanner</h3>
      <input id="urlInput" value="http://sbi-kyc-update-alert.xyz/login" />
      <button class="danger" onclick="scanUrl()">Analyze URL</button>
      <button onclick="document.getElementById('urlInput').value='https://www.onlinesbi.sbi'; scanUrl()">Test Safe URL</button>
    </div>

    <div class="card">
      <h3>2. Scam SMS Filter</h3>
      <textarea id="smsInput" rows="3">URGENT: Your SBI YONO account will be blocked today! Update PAN KYC immediately at http://sbi-kyc.xyz</textarea>
      <button class="danger" onclick="scanSms()">Analyze SMS</button>
    </div>

    <div class="card">
      <h3>3. Network Intrusion Monitor</h3>
      <p style="font-size:13px; color:#cbd5e1;">Simulate live packet flow capture (Scapy / CICIDS features):</p>
      <button class="danger" onclick="scanNet(4500, 60, 0.96, 1, 1)">Simulate SYN Flood</button>
      <button class="danger" onclick="scanNet(850, 64, 0.85, 1024, 0)">Simulate Port Scan</button>
      <button onclick="scanNet(25, 720, 0.03, 1, 1)">Normal Traffic</button>
    </div>
  </div>

  <div id="output" class="result"></div>

  <script>
    async function renderResult(res) {
      const box = document.getElementById('output');
      const d = res.detection;
      const a = res.advisory;
      box.style.display = 'block';
      box.className = 'result ' + (d.is_threat ? 'threat' : 'safe');
      box.innerHTML = `
        <h3 style="margin-top:0;">${d.is_threat ? '🚨 THREAT DETECTED' : '✅ SAFE'}: ${d.vector} [${d.severity}]</h3>
        <p><strong>Confidence:</strong> ${(d.confidence*100).toFixed(1)}% | <strong>Stage 1 Latency:</strong> ${d.stage1_latency_ms} ms | <strong>Stage 2 Runtime:</strong> <code>${a.runtime}</code></p>
        <p><strong>Technical Indicators:</strong> ${d.indicators.join(' • ')}</p>
        <hr style="border-color:#334155;">
        <h4>Plain-Language Explanation (Llama 3.2 1B via ExecuTorch):</h4>
        <p>${a.explanation}</p>
        <h4>Recommended Remediation Actions:</h4>
        <ul>${a.remediation.map(r => `<li>${r}</li>`).join('')}</ul>
      `;
    }
    async function scanUrl() {
      const r = await fetch('/api/scan/url', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({content: document.getElementById('urlInput').value}) });
      renderResult(await r.json());
    }
    async function scanSms() {
      const r = await fetch('/api/scan/sms', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({content: document.getElementById('smsInput').value}) });
      renderResult(await r.json());
    }
    async function scanNet(pps, avg_bytes, syn_ratio, dst_ports, external) {
      const r = await fetch('/api/scan/network', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({pps, avg_bytes, syn_ratio, dst_ports, external}) });
      renderResult(await r.json());
    }
  </script>
</body>
</html>
"""
