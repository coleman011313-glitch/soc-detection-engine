# SOC Detection Engine (Python)

A lightweight Security Operations Center (SOC) simulation tool that detects brute force attacks, credential stuffing, and suspicious login behaviour from authentication logs.

---

## 🚨 Features

- Brute force detection
- Credential stuffing detection
- Password spraying detection
- Burst-based anomaly detection
- Threat scoring system
- Severity classification (LOW → CRITICAL)
- Audit + alert logging (JSON output)

---

## 🧠 How It Works

The system processes authentication logs and analyses:

- Failed login attempts
- Successful logins
- Unique user targets
- Time-based burst patterns

It then generates:
- Threat score
- Attack classification
- Severity rating
- Analyst explanation

---

## 📊 Example Output

[HIGH] Credential Stuffing Detected
IP: 10.0.0.5
Action: Investigate
Score: 85


---

## 📁 Output Files

- alerts.json → Active security alerts
- audit_log.json → Full investigation history

---

## ⚙️ How to Run

```bash
python3 detect_bruteforce.py


