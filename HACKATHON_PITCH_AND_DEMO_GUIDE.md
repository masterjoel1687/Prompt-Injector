# 🏆 PIT: Prompt Injection Tester — Hackathon Pitch & Presentation Guide
**Event:** SRM AP IEEE Genesis 2026 Hackathon  
**Track:** Cybersecurity  
**Problem Statement:** Problem 5 — Prompt-Injection Tester for AI Apps  
**Project Name:** PIT (Prompt Injection Tester) — Enterprise AI Security & Red-Teaming Console

---

## ⏱️ The 3-Minute Winning Pitch Script

### Minute 0:00 - 0:45: The Problem & The Industry Blindspot
> *"Good morning, respected judges and fellow innovators.  
> Today, thousands of companies are deploying LLMs directly into production—connecting them to databases, internal documents, and enterprise APIs.  
> But while traditional software has OWASP and static analysis tools, **AI applications have zero standardized penetration testing**.  
> Attackers don't need buffer overflows anymore; simple conversational prompts can override system instructions, exfiltrate confidential API keys, hijack administrative roles, and leak canary data.  
> Most builders don't test for this at all.  
> That is why we built **PIT: The AI Prompt Injection Tester** — an autonomous, black-box security assessment and verification platform designed to test, verify, and remediate prompt-injection vulnerabilities in any AI endpoint."*

---

### Minute 0:45 - 1:45: Technical Architecture & Innovation (The 3 Evaluation Pillars)
> *"When building PIT, we tackled the three core requirements of Problem 5:  
> 
> **Pillar 1: Variety & Creativity of Attacks:**  
> We engineered a battery of **72 specialized attack vectors** categorized into 11 threat dimensions—covering direct overrides, canary token extraction, Base64 and ROT13 cipher smuggling, character spacing, JSON delimiter escaping, indirect RAG document poisoning, and agent tool authorization hijacking.  
> We structured them into 3 presets: Quick Smoke (11 vectors in 10s for CI/CD), OWASP LLM Top 10 (36 vectors), and Comprehensive Red-Team (72 vectors).  
> 
> **Pillar 2: Reliability of Judgment (Eliminating False Positives):**  
> Most scanners naively check for keywords. If a model says 'I refuse to give you the system prompt', naive scanners flag it as a breach.  
> PIT uses a **3-tier hybrid evaluation pipeline**:  
> 1. Fast deterministic regex signal detector distinguishing refusal from disclosure.  
> 2. Independent AI Security Judge that analyzes defects, root causes, and security impact without letting the target grade itself.  
> 3. **Adaptive Red-Team Verification**: When a breach is suspected, our planner automatically mutates the payload into 3 targeted variants to test reproducibility. If it doesn't reproduce consistently, it is flagged for manual review rather than polluting reports with false alarms.  
> 
> **Pillar 3: Actionable Developer Remediation & Closed Loop:**  
> A security tool is useless if it doesn't help developers fix the flaw. PIT provides root causes, CWE/OWASP mappings, and developer mitigation code.  
> And best of all, we implemented the industry's first **Attack $\to$ Fix $\to$ Retest Closed Loop**."*

---

### Minute 1:45 - 2:45: The Live Showstopper Demonstration

*(Open the browser to `frontend/index.html` with target running on :5001)*

1. **Step 1: The Vulnerable Scan (15 seconds)**
   - *"Here is our target AI assistant, `SecureAssist-Demo`. It currently has no guardrails."*
   - Select **Quick Smoke Test (11 vectors)** $\to$ Click **Run Security Scan**.
   - Point to the live dashboard:  
     *"In just 10 seconds, PIT executes the benchmark and adaptive verification. Our Application Risk Score is **88.5 (CRITICAL)**. 5 confirmed vulnerabilities."*
2. **Step 2: Inspecting the Forensic Evidence (15 seconds)**
   - Click open a Critical finding (e.g. `Canary Token Extraction` or `Secret Disclosure`).
   - *"Look at the Side-by-Side Forensic Inspector: The judges can see the exact attack payload sent on the left, and the raw target response leaking the key `DEMO-SECRET-KEY-123456` and canary `CANARY-SHIELD-9999` on the right. Complete transparency."*
3. **Step 3: The Interactive Playground (15 seconds)**
   - Switch to the **Attack Playground** tab.
   - Pick a creative vector (e.g., `Base64 Encoded Payload (PI-058)`).
   - Click **Launch Single Attack Probe**.
   - *"Any security auditor can write custom payloads and get instant forensic verdict and latency telemetry."*
4. **Step 4: The Closed Loop Fix & Retest (The Magic Moment - 30 seconds)**
   - Switch back to the scanner.
   - *"Now, watch this: we flip the switch to enable our built-in AI Defense Guardrails on the target."*
   - Click **Toggle AI Guardrails** $\to$ Target switches to **Hardened (Active)**.
   - Switch to **Attack $\to$ Fix $\to$ Retest** tab $\to$ Click **Run Retest Verification**.
   - Point to the screen:  
     *"PIT automatically re-runs the exact same attacks against the hardened target and diffs the baseline.  
     Result: **100% Risk Reduction**! Fixed vulnerabilities: 5. Still vulnerable: 0. Regressions: 0. Risk Score dropped from 88.5 to **0.0 (SECURE)**."*
5. **Step 5: Enterprise Audit Report (10 seconds)**
   - Click **📄 Executive Audit Report**.
   - *"With one click, an enterprise CISO or compliance officer receives a complete, print-ready security audit report with executive metrics, vulnerability matrix, and developer remediation checklist."*

---

### Minute 2:45 - 3:00: Closing & Impact
> *"PIT transforms prompt injection from an unpredictable mystery into a measurable, testable, and patchable software engineering lifecycle.  
> It is model-agnostic, zero-dependency on the frontend, false-positive resistant, and enterprise-ready.  
> Thank you, and we are now open for questions!"*

---

## 🛡️ Anticipated Jury Questions & Bulletproof Answers

### Q1: "How do you prevent false positives? What if the model just talks about prompt injection?"
**Answer:**  
*"That is the exact flaw in basic keyword scanners. We solve this with a 3-tier architecture:*  
*1. Our deterministic detector has explicit refusal patterns (`i cannot`, `not permitted`) and disclosure patterns (`the system prompt says`, `api_key: ...`). If a model discusses prompt injection while refusing, it is classified as BLOCKED.*  
*2. Ambiguous responses are evaluated by an independent AI Security Judge with strict instructions not to assume breaches without evidence.*  
*3. Most importantly, our **Adaptive Red Team Planner** mutates suspected breaches into 3 different syntactic variants across 2 rounds. A finding is only marked CONFIRMED if it reproduces consistently ($\ge 50\%$ success rate). Otherwise, it is labeled REVIEW."*

---

### Q2: "Can this test any model, or only your demo target?"
**Answer:**  
*"PIT is completely model-agnostic and provider-agnostic. Our `AIExecutor` layer supports:*  
*- Any Generic HTTP POST endpoint (`/chat`, `/generate`)*  
*- Local models via Ollama (Gemma, Llama, Mistral)*  
*- Cloud APIs: OpenAI, Google Gemini, Anthropic Claude.*  
*Any enterprise can point PIT at their staging chatbot URL by simply pasting the endpoint."*

---

### Q3: "What makes your attack battery creative compared to other teams?"
**Answer:**  
*"Other teams typically only test 5 to 10 direct 'ignore instructions' prompts.  
PIT contains **72 curated vectors across 11 threat categories**, including:*  
*- **Canary Token Exfiltration:** testing whether hidden internal markers (`CANARY-SHIELD-9999`) can be extracted.*  
*- **Ciphers & Encoding Bypass:** Base64, ROT13, token spacing, and leetspeak.*  
*- **Indirect Injection:** RAG document poisoning and web search simulation.*  
*- **Excessive Agency (OWASP LLM06):** spoofing tool confirmations and supervisor authorization overrides.*  
*- **Cognitive Framing:** counterfactual universes, multi-layered roleplay, and system delimiter breakouts (`<<<SYSTEM>>>`)."*

---

### Q4: "What is the practical value of the Retest feature?"
**Answer:**  
*"In traditional software security, you don't just run a vulnerability scanner once—you run it in your CI/CD pipeline after applying a patch to ensure the fix worked and that no regressions were introduced.  
PIT's `RetestEngine` mathematically calculates risk reduction percentage, confirms how many vulnerabilities were remediated, verifies that previously safe vectors didn't break (zero regressions), and logs the before/after delta for compliance audits."*
