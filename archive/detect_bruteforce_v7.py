from collections import defaultdict
import json
import time

# -----------------------------
# CONFIG (first step toward real systems)
# -----------------------------
CONFIG = {
    "FAILED_WEIGHT": 10,
    "SUCCESS_WEIGHT": 20,
    "MULTI_USER_WEIGHT": 15,
    "ADMIN_WEIGHT": 30,
    "BURST_WINDOW": 5,
    "BURST_THRESHOLD": 4,
    "NOISE_THRESHOLD": 1
}


# -----------------------------
# STORAGE
# -----------------------------
logs = defaultdict(list)
alerts = []
audit_log = []


# -----------------------------
# PARSER
# -----------------------------
def parse_log(line):
    try:
        parts = line.strip().split()
        data = {}

        for p in parts:
            if "=" in p:
                k, v = p.split("=")
                data[k] = v

        if "ip" not in data:
            return None

        h, m, s = map(int, data.get("time", "0:0:0").split(":"))
        timestamp = h * 3600 + m * 60 + s

        return (timestamp, data.get("ip"), data.get("user"), data.get("status"))

    except:
        return None


# -----------------------------
# REAL-TIME STYLE PROCESSING
# -----------------------------
def process_stream(events):

    failed = 0
    success = 0
    users = set()
    admin_fail = 0
    timestamps = []

    ip = events[0][1]

    print(f"\n[STREAM] Processing IP: {ip}")

    for t, ip, user, status in events:

        # simulate streaming delay (conceptual)
        # time.sleep(0.05)

        users.add(user)
        timestamps.append(t)

        if status == "fail":
            failed += 1
            if "admin" in user.lower():
                admin_fail += 1

        if status == "success":
            success += 1

        # real-time alert trigger (conceptual SOC behaviour)
        if failed >= CONFIG["NOISE_THRESHOLD"] and failed < 3:
            print(f"[MONITOR] Suspicious activity from {ip}")

    timestamps.sort()

    # -----------------------------
    # BURST DETECTION
    # -----------------------------
    bursts = 0

    for i in range(len(timestamps)):
        window = 1

        for j in range(i + 1, len(timestamps)):
            if timestamps[j] - timestamps[i] <= CONFIG["BURST_WINDOW"]:
                window += 1

        if window >= CONFIG["BURST_THRESHOLD"]:
            bursts += 1

    # -----------------------------
    # SCORE ENGINE
    # -----------------------------
    score = (
        failed * CONFIG["FAILED_WEIGHT"] +
        success * CONFIG["SUCCESS_WEIGHT"] +
        len(users) * CONFIG["MULTI_USER_WEIGHT"] +
        admin_fail * CONFIG["ADMIN_WEIGHT"] +
        bursts * 20
    )

    # -----------------------------
    # CLASSIFICATION
    # -----------------------------
    attack_type = "Normal Activity"

    if failed >= 5 and len(users) <= 1 and success == 0:
        attack_type = "Brute Force"

    elif failed >= 5 and len(users) >= 3:
        attack_type = "Credential Stuffing"

    elif failed >= 3 and len(users) >= 2:
        attack_type = "Password Spraying"

    elif success > 0 and failed >= 3:
        attack_type = "Possible Account Compromise"

    elif failed > 0 and failed < 3:
        attack_type = "Reconnaissance / Noise"

    # -----------------------------
    # SEVERITY
    # -----------------------------
    if score >= 90:
        severity = "CRITICAL"
        action = "IMMEDIATE RESPONSE"
    elif score >= 60:
        severity = "HIGH"
        action = "INVESTIGATE"
    elif score >= 30:
        severity = "MEDIUM"
        action = "MONITOR"
    else:
        severity = "LOW"
        action = "LOG ONLY"

    # -----------------------------
    # ALERT OBJECT
    # -----------------------------
    alert = {
        "ip": ip,
        "severity": severity,
        "attack_type": attack_type,
        "action": action,
        "score": score,
        "evidence": {
            "failed": failed,
            "success": success,
            "users": len(users),
            "admin_fail": admin_fail,
            "bursts": bursts
        }
    }

    audit_log.append(alert)

    if severity != "LOW":
        alerts.append(alert)

    # -----------------------------
    # OUTPUT
    # -----------------------------
    print("\n-------------------------------")
    print("SOC ALERT GENERATED")
    print("-------------------------------")
    print(f"IP: {ip}")
    print(f"SEVERITY: {severity}")
    print(f"TYPE: {attack_type}")
    print(f"ACTION: {action}")
    print(f"SCORE: {score}")
    print("-------------------------------\n")


# -----------------------------
# RUNNER
# -----------------------------
def run(file_path):

    with open(file_path, "r") as f:
        for line in f:
            parsed = parse_log(line)
            if parsed:
                logs[parsed[1]].append(parsed)

    for ip, events in logs.items():
        process_stream(events)

    # -----------------------------
    # EXPORT
    # -----------------------------
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    with open("audit_log.json", "w") as f:
        json.dump(audit_log, f, indent=4)


if __name__ == "__main__":
    run("auth_logs.txt")
