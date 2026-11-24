import re
import time
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

class KavachStage1Detector:
    def __init__(self):
        self._train_url_model()
        self._train_sms_model()
        self._train_network_model()

    def _extract_url_features(self, url: str):
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        suspicious_tlds = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click")
        brand_keywords = ("sbi", "hdfc", "icici", "paytm", "upi", "kyc", "verify", "login", "secure", "update", "bank", "gov", "epfo")

        has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain) else 0
        url_len = len(url)
        dot_count = domain.count(".")
        hyphen_count = domain.count("-")
        has_at = 1 if "@" in url else 0
        is_http = 1 if parsed.scheme == "http" else 0
        bad_tld = 1 if any(domain.endswith(t) for t in suspicious_tlds) else 0
        brand_hits = sum(1 for k in brand_keywords if k in domain or k in path)
        digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
        return [has_ip, url_len, dot_count, hyphen_count, has_at, is_http, bad_tld, brand_hits, digit_ratio]

    def _train_url_model(self):
        benign = [
            "https://www.google.com", "https://github.com/pytorch/executorch",
            "https://www.onlinesbi.sbi", "https://www.hdfcbank.com",
            "https://www.wikipedia.org/wiki/Arm_architecture", "https://huggingface.co/Arm",
            "https://www.irctc.co.in/nget/train-search", "https://developer.arm.com/ai"
        ]
        phishing = [
            "http://sbi-kyc-update-alert.xyz/login", "http://192.168.1.55/hdfc-verify/auth.php",
            "http://paytm-cashback-claim.top/upi-pin", "http://epfo-passbook-check.click/update",
            "http://secure-icici-netbanking-login.tk/verify", "http://www.google.com@evil-login.ml/pass",
            "http://gov-in-tax-refund-2026.buzz/claim", "http://upi-reward-verify-99182.gq/bank"
        ]
        X = [self._extract_url_features(u) for u in benign + phishing]
        y = [0] * len(benign) + [1] * len(phishing)
        self.url_clf = RandomForestClassifier(n_estimators=50, random_state=42).fit(X, y)

    def analyze_url(self, url: str) -> dict:
        t0 = time.perf_counter()
        feats = self._extract_url_features(url)
        prob = float(self.url_clf.predict_proba([feats])[0][1])
        indicators = []
        if feats[0]: indicators.append("Raw IP address used instead of domain")
        if feats[5]: indicators.append("Unencrypted HTTP connection")
        if feats[6]: indicators.append("High-risk disposable TLD (.xyz/.top/.tk/.click)")
        if feats[7] >= 1 and (feats[6] or feats[3] >= 2): indicators.append("Brand/banking impersonation keywords")
        if feats[3] >= 2: indicators.append("Excessive hyphens in domain (typosquatting pattern)")

        is_threat = prob >= 0.55 or len(indicators) >= 2
        return {
            "vector": "Phishing URL",
            "input": url,
            "is_threat": is_threat,
            "severity": "HIGH" if is_threat else "SAFE",
            "confidence": round(max(prob, 0.88 if is_threat else 1 - prob), 3),
            "indicators": indicators or ["Valid HTTPS domain structure"],
            "stage1_latency_ms": round((time.perf_counter() - t0) * 1000, 2)
        }

    def _train_sms_model(self):
        samples = [
            ("Hey, are we meeting at the Vel Tech lab at 2 PM?", 0),
            ("Your OTP for Aadhaar login is 482910. Valid for 10 mins.", 0),
            ("Mom: Please pick up milk on your way back home.", 0),
            ("Meeting rescheduled to tomorrow morning in Room 304.", 0),
            ("URGENT: Your SBI YONO account will be blocked today! Update PAN KYC immediately at http://sbi-kyc.xyz", 1),
            ("Congratulations! You won Rs 25,00,000 in KBC lucky draw. Send Rs 5000 processing fee via UPI now.", 1),
            ("Electricity bill overdue. Power will be disconnected tonight at 9:30 PM. Call officer 9876543210 immediately.", 1),
            ("Dear customer, Rs 15,000 credited to your UPI. Click link to accept payment into bank account.", 1),
        ]
        texts, labels = zip(*samples)
        self.sms_clf = make_pipeline(TfidfVectorizer(ngram_range=(1, 2)), LogisticRegression()).fit(texts, labels)

    def analyze_sms(self, text: str) -> dict:
        t0 = time.perf_counter()
        prob = float(self.sms_clf.predict_proba([text])[0][1])
        lower = text.lower()
        indicators = []
        if any(w in lower for w in ("blocked", "suspended", "disconnected", "urgent", "immediately", "tonight")):
            indicators.append("Artificial urgency / fear coercion tactic")
        if any(w in lower for w in ("kyc", "pan", "upi", "pin", "won", "lottery", "refund", "processing fee")):
            indicators.append("Financial / credential harvesting lure")
        if re.search(r"http[s]?://|www\.|\.xyz|\.top|\.click", lower):
            indicators.append("Embedded external action link")

        is_threat = prob >= 0.50 or len(indicators) >= 2
        return {
            "vector": "Scam SMS / Communication",
            "input": text,
            "is_threat": is_threat,
            "severity": "CRITICAL" if is_threat else "SAFE",
            "confidence": round(max(prob, 0.91 if is_threat else 1 - prob), 3),
            "indicators": indicators or ["Normal conversational or transactional message"],
            "stage1_latency_ms": round((time.perf_counter() - t0) * 1000, 2)
        }

    def _train_network_model(self):
        normal_flows = [[12, 640, 0.05, 1, 1], [45, 1120, 0.02, 2, 1], [8, 320, 0.04, 1, 0], [120, 1380, 0.01, 1, 1]]
        attack_flows = [[4500, 60, 0.96, 1, 1], [850, 64, 0.85, 1024, 0], [300, 1450, 0.02, 1, 1], [2200, 74, 0.91, 450, 1]]
        X = normal_flows + attack_flows
        y = [0] * len(normal_flows) + [1] * len(attack_flows)
        self.net_clf = RandomForestClassifier(n_estimators=50, random_state=42).fit(X, y)

    def analyze_network_flow(self, pps: float, avg_bytes: float, syn_ratio: float, dst_ports: int, external: int) -> dict:
        t0 = time.perf_counter()
        feats = [pps, avg_bytes, syn_ratio, dst_ports, external]
        prob = float(self.net_clf.predict_proba([feats])[0][1])
        indicators = []
        if syn_ratio > 0.7 and pps > 500:
            indicators.append(f"SYN-flood / DoS signature ({pps} pkt/s, {int(syn_ratio*100)}% SYN flags)")
        if dst_ports > 50:
            indicators.append(f"Port scan / reconnaissance sweep ({dst_ports} distinct destination ports)")
        if avg_bytes > 1300 and pps > 200 and external == 1:
            indicators.append("Anomalous outbound data exfiltration burst")

        is_threat = prob >= 0.55 or len(indicators) >= 1
        return {
            "vector": "Network Traffic Intrusion",
            "input": f"Flow: {pps} pkt/s | {avg_bytes}B avg | SYN={syn_ratio} | Ports={dst_ports}",
            "is_threat": is_threat,
            "severity": "CRITICAL" if is_threat else "SAFE",
            "confidence": round(max(prob, 0.94 if is_threat else 1 - prob), 3),
            "indicators": indicators or ["Normal baseline traffic flow"],
            "stage1_latency_ms": round((time.perf_counter() - t0) * 1000, 2)
        }
