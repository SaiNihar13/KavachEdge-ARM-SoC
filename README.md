# KavachEdge: On-Device AI Threat Detection & Security Assistant

> **Zero-Cloud, Real-Time Cybersecurity & Plain-Language Threat Advisory Powered by Llama and ExecuTorch on Arm Edge Hardware.**

**Submission for:** ARM Bharat AI-SoC Challenge 2026–27 (Theme: Cybersecurity & Digital Safety)  
**Team 3:** Seku Sri Sai Nihar, Leagashmi, Sai Charan  

---

## 1. Overview
**KavachEdge** is a completely offline, privacy-preserving edge cybersecurity assistant designed for Arm-based edge devices (Raspberry Pi 5, Arm Linux, and Arm64 Android). It detects multi-vector cyber threats locally—without sending sensitive network packets, messages, or URLs to the cloud—and translates technical alerts into plain-language explanations and actionable remediation steps for non-expert users.

## 2. Two-Stage Edge Architecture
To achieve sub-10 ms threat detection alongside low-memory LLM reasoning on resource-constrained Arm hardware, KavachEdge separates inference into two stages:

1. **Stage 1 — Fast Deterministic Threat Detection (< 5 ms):**
   * **Phishing URL Classifier:** Lexical and structural feature extraction (IP-in-URL, TLD risk, domain entropy, brand impersonation tokens) classified via Random Forest (PhishTank / OpenPhish patterns).
   * **Scam SMS & Communication Filter:** N-gram TF-IDF + Logistic Regression trained to flag social engineering urgency, KYC/UPI lures, and malicious links (UCI SMS Spam Collection + Indian digital fraud patterns).
   * **Network Traffic Intrusion Detector:** Flow-level anomaly detection (Scapy / libpcap packet features aligned with CICIDS2017 & UNSW-NB15) identifying SYN floods, port scans, and abnormal outbound bursts.
2. **Stage 2 — On-Device LLM Reasoning & Advisory (Llama 3.2 1B + ExecuTorch):**
   * Runs `Arm/llama3-2-1b-instruct-int8-xnnpack-executorch-raspberrypi5` (`model.pte`, INT8 quantized, ~1.76 GB) locally via the **ExecuTorch** runtime with the **XNNPACK** CPU backend.
   * Triggered only on flagged threats to generate concise, plain-language explanations and 3-step remediation guidance.
   * *(Optional Hardware Acceleration Note)*: When deployed on Raspberry Pi 5 with AI HAT+ / AI HAT+ 2, Stage 1 neural workloads execute on the Hailo NPU via **HailoRT**, while **Llama 3.2 1B** runs independently on the Arm CPU via **ExecuTorch**.

## 3. Repository Structure
* `app.py` — FastAPI backend & zero-cloud local web dashboard
* `stage1_detector.py` — Sub-5ms URL, Scam SMS, and Network Intrusion detectors
* `stage2_advisor.py` — ExecuTorch runtime loader & Llama 3.2 1B advisory engine
* `requirements.txt` — Python dependencies
* `README.md` — Project documentation

## 4. Quickstart Setup (Local Offline Execution)

1. **Create Environment & Install Dependencies:**
   `python3 -m venv ~/kavach-venv && source ~/kavach-venv/bin/activate && pip install -r requirements.txt`
2. **Download Arm-Optimized ExecuTorch `.pte` Model:**
   `mkdir -p models/llama3_2_1b_arm`
   `python3 -c 'from huggingface_hub import snapshot_download; snapshot_download(repo_id="Arm/llama3-2-1b-instruct-int8-xnnpack-executorch-raspberrypi5", local_dir="models/llama3_2_1b_arm")'`
   `python3 -c 'from huggingface_hub import hf_hub_download; hf_hub_download(repo_id="unsloth/Llama-3.2-1B-Instruct", filename="tokenizer.json", local_dir="models/llama3_2_1b_arm")'`
3. **Launch the Offline Dashboard:**
   `uvicorn app:app --host 127.0.0.1 --port 8000`
   Open `[http://127.0.0.1:8000](http://127.0.0.1:8000)` in your browser and disconnect Wi-Fi/internet to verify 100% zero-cloud local inference.
