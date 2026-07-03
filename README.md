# 🛡️ SOC Detection Engine — Brute Force & Credential Attack Monitor

## 📌 Overview

This project is a Python-based **Security Operations Center (SOC) detection engine** designed to analyse authentication logs and detect suspicious login behaviour such as:

- Brute force attacks
- Credential stuffing attempts
- Rapid automated login activity (bot behaviour)
- Admin account targeting
- Distributed login attempts across multiple users

The system uses a **risk scoring model combined with time-based analysis** to classify threats.

---

## ⚙️ How It Works

The engine reads authentication logs in the format:

user=alice ip=10.0.0.5 status=fail time=10:00:01


It extracts:
- Username
- IP address
- Login status (success/fail)
- Timestamp

Then it groups events by IP and analyses behaviour patterns.

---

## 🧠 Detection Method

This system uses a **behaviour-based risk scoring model**:

### 🔢 Scoring Rules

- Failed login attempt → +10 points  
- Multiple unique users targeted → +5 points  
- Rapid login attempts (≤2 seconds apart) → +10 points  
- High event rate (bot-like behaviour) → +20 points  
- Admin account failures → increases investigation priority  

---

## 📊 Severity Classification

| Score Range | Severity |
|-------------|----------|
| 0–29        | LOW |
| 30–59       | MEDIUM |
| 60–89       | HIGH |
| 90+         | CRITICAL |

---

## ⏱ Time-Based Analysis

The system calculates:

- Total activity duration per IP
- Failed login rate (events per second)

This helps distinguish:

- 👤 Human error → slow, spaced attempts  
- 🤖 Automated attack → fast, repeated attempts  

---

## 📁 Project Structure

soc-detection-engine/
│
├── detect_bruteforce.py # Main SOC detection engine
├── auth_logs.txt # Sample authentication logs
├── README.md # Project documentation


---

## 🚀 How to Run

```bash
python3 detect_bruteforce.py

IP ADDRESS: 192.168.1.20
THREAT SCORE: 70
SEVERITY: HIGH
--------------------------------------------------
SUMMARY:
- 4 failed login attempts
- 1 successful login
- 1 different user targeted
- Activity duration: 8 seconds
- Failed login rate: 0.5 per second

DETAILS:
Failed logins: 4
Successful logins: 1
Unique users: 1
Admin failures: 0
