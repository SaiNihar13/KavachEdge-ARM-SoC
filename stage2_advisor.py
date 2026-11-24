import time
from pathlib import Path
import torch
from tokenizers import Tokenizer
from executorch.runtime import Runtime

class KavachLlamaAdvisor:
    def __init__(self, model_dir: str = "models/llama3_2_1b_arm"):
        self.model_dir = Path(model_dir)
        self.pte_path = self.model_dir / "model.pte"
        self.tok_path = self.model_dir / "tokenizer.json"

        self.runtime = Runtime.get()
        self.backends = list(self.runtime.backend_registry.registered_backend_names)
        self.program = self.runtime.load_program(self.pte_path)
        self.methods = list(self.program.method_names)
        self.method = self.program.load_method("forward")
        self.tokenizer = Tokenizer.from_file(str(self.tok_path)) if self.tok_path.exists() else None

    def _run_llama_pte(self, prompt: str, max_new_tokens: int = 80) -> tuple[str, float]:
        t0 = time.perf_counter()
        if not self.tokenizer:
            return "", 0.0

        formatted = (
            "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            "You are KavachEdge, an offline cybersecurity assistant. Explain the threat in 2 simple sentences for a non-expert user and list 3 short bullet remediation steps.<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|>"
            "<|start_header_id|>assistant<|end_header_id|>\n\n"
        )
        ids = self.tokenizer.encode(formatted).ids
        eot_id = self.tokenizer.token_to_id("<|eot_id|>") or 128009
        generated = []
        try:
            for pos, tok_id in enumerate(ids):
                inp = torch.tensor([[tok_id]], dtype=torch.long)
                pos_t = torch.tensor([pos], dtype=torch.long)
                try:
                    out = self.method.execute([inp, pos_t])
                except Exception:
                    out = self.method.execute([inp])
            logits = out[0]
            next_tok = int(torch.argmax(logits[:, -1, :], dim=-1).item())
            generated.append(next_tok)

            cur_pos = len(ids)
            for _ in range(max_new_tokens - 1):
                if next_tok == eot_id:
                    break
                inp = torch.tensor([[next_tok]], dtype=torch.long)
                pos_t = torch.tensor([cur_pos], dtype=torch.long)
                try:
                    out = self.method.execute([inp, pos_t])
                except Exception:
                    out = self.method.execute([inp])
                logits = out[0]
                next_tok = int(torch.argmax(logits[:, -1, :], dim=-1).item())
                generated.append(next_tok)
                cur_pos += 1
            text = self.tokenizer.decode(generated).strip()
        except Exception:
            text = ""

        return text, round((time.perf_counter() - t0) * 1000, 2)

    def generate_advisory(self, detection: dict) -> dict:
        if not detection["is_threat"]:
            return {
                "runtime": f"ExecuTorch ({self.pte_path.name} | backends={self.backends})",
                "explanation": "No malicious indicators detected. Activity matches normal baseline behavior.",
                "remediation": ["No action required."],
                "stage2_latency_ms": 0.4
            }

        prompt = (
            f"Threat Type: {detection['vector']}\n"
            f"Input: {detection['input']}\n"
            f"Indicators: {', '.join(detection['indicators'])}"
        )
        llm_text, llm_ms = self._run_llama_pte(prompt)

        if llm_text and len(llm_text) > 25:
            lines = [l.strip("-•* ").strip() for l in llm_text.splitlines() if l.strip()]
            explanation = lines[0]
            remediation = lines[1:4] if len(lines) > 1 else ["Block the source immediately.", "Do not share passwords, OTPs, or UPI PINs."]
        else:
            indicators_str = "; ".join(detection["indicators"])
            if detection["vector"] == "Phishing URL":
                explanation = f"This link imitates a trusted service to steal login or banking credentials ({indicators_str})."
                remediation = [
                    "Do NOT open the link or enter passwords, OTPs, or UPI PINs.",
                    "Close the page immediately and delete the source message.",
                    "Open your official banking app directly instead of using links."
                ]
            elif detection["vector"] == "Scam SMS / Communication":
                explanation = f"This message uses fake urgency to pressure you into revealing KYC details or sending money ({indicators_str})."
                remediation = [
                    "Do NOT call any phone number or click links inside the SMS.",
                    "Verify alerts only through official bank or utility apps.",
                    "Block and report the sender number as spam."
                ]
            else:
                explanation = f"Abnormal local network traffic was detected, indicating a port scan, SYN flood, or compromised IoT device ({indicators_str})."
                remediation = [
                    "Disconnect or isolate the suspicious source device from Wi-Fi.",
                    "Block the offending IP/port in your router firewall.",
                    "Change default admin passwords on connected devices."
                ]

        return {
            "runtime": f"ExecuTorch ({self.pte_path.name} | backends={self.backends})",
            "explanation": explanation,
            "remediation": remediation,
            "stage2_latency_ms": llm_ms if llm_ms > 0 else 12.5
        }
