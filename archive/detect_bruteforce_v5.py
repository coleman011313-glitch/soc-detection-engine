from collections import defaultdict
import json

# -----------------------------
# CONFIG
# -----------------------------
FAILED_WEIGHT = 10
SUCCESS_WEIGHT = 20
MULTI_USER_WEIGHT = 15
ADMIN_WEIGHT = 30
BURST_WINDOW = 5
BURST_THRESHOLD = 4

# -----------------------------
# STORAGE
# -----------------------------
logs = defaultdict(list)
alerts = []
audit_log = []


# -----------------------------
# PARSER (FIXED + SAFE)
# -----------------------------
def parse_log(line):
    try:
        parts = line.strip().split()

        data = {}

        for p in parts:
            if "=" in p:
                key, value = p.split("=")
                data[key] = value

        # prevent broken logs
        if "ip" not in data or "user" not in data or "status" not in data:
            return None

        h, m, s = map(int, data.get("time", "0:0:0").split(":"))
        timestamp = h * 3600 + m * 60 + s

        return (
            timestamp,
            data.get("ip"),
            data.get("user"),
            data.get("status")
        )

    except:
        return None


# -----------------------------
# ANALYSIS ENGINE
# -----------------------------
def analyze_ip(events):

    if not events:
        return

    failed = 0
    success = 0
    users = set()
    admin_fail = 0
    timestamps = []

    ip_address = events[0][1]

    for t, ip, user, status in events:
        users.add(user)
        timestamps.append(t)

        if status == "fail":
            failed += 1
            if "admin" in user.lower():
                admin_fail += 1

        if status == "success":
            success += 1

    timestamps.sort()

    # -----------------------------
    # BURST DETECTION
    # -----------------------------
    bursts = 0

    for i in range(len(timestamps)):
        window = 1

        for j in range(i + 1, len(timestamps)):
            if timestamps[j] - timestamps[i] <= BURST_WINDOW:
                window += 1

        if window >= BURST_THRESHOLD:
            bursts += 1

    # -----------------------------
    # SCORE
    # -----------------------------
    score = (
        failed * FAILED_WEIGHT +
        success * SUCCESS_WEIGHT +
        len(users) * MULTI_USER_WEIGHT +
        admin_fail * ADMIN_WEIGHT +
        bursts * 20
    )

    # -----------------------------
    # ATTACK TYPE (IMPROVED COVERAGE)
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
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # -----------------------------
    # ALERT DECISION
    # -----------------------------
    alert = {
        "ip": ip_address,
        "severity": severity,
        "attack_type": attack_type,
        "score": score,
        "failed": failed,
        "success": success,
        "users": len(users),
        "admin_fail": admin_fail,
        "bursts": bursts
    }

    # ALWAYS store in audit log
    audit_log.append(alert)

    # ONLY push real alerts
    if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
        alerts.append(alert)

    # -----------------------------
    # OUTPUT
    # -----------------------------
    print("\n==================================================")
    print("SOC ALERT")
    print("==================================================")

    print(f"\nSEVERITY   : {severity}")
    print(f"ATTACK     : {attack_type}")
    print(f"IP         : {ip_address}")
    print(f"SCORE      : {score}")

    print("\nSUMMARY")
    print(f"- Failed: {failed}")
    print(f"- Success: {success}")
    print(f"- Users: {len(users)}")
    print(f"- Bursts: {bursts}")

    print("\n==================================================\n")


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
        analyze_ip(events)

    # -----------------------------
    # EXPORTS
    # -----------------------------
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    with open("audit_log.json", "w") as f:
        json.dump(audit_log, f, indent=4)


if __name__ == "__main__":
    run("auth_logs.txt")
