from collections import defaultdict
import json

# -----------------------------
# CONFIG
# -----------------------------
FAILED_WEIGHT = 10
SUCCESS_WEIGHT = 20
MULTI_USER_WEIGHT = 15
ADMIN_WEIGHT = 30

BURST_WINDOW = 5  # seconds
BURST_THRESHOLD_COUNT = 4


# -----------------------------
# PARSER
# -----------------------------
def parse_log(line):
    try:
        parts = line.strip().split()

        data = {}

        for p in parts:
            if "=" in p:
                key, value = p.split("=")
                data[key] = value

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
# ANALYSIS
# -----------------------------
logs = defaultdict(list)


def analyze_ip(events):

    failed = 0
    success = 0
    users = set()
    admin_fail = 0

    timestamps = []

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
    # REAL BURST DETECTION
    # -----------------------------
    bursts = 0

    for i in range(len(timestamps)):
        window_count = 1

        for j in range(i + 1, len(timestamps)):
            if timestamps[j] - timestamps[i] <= BURST_WINDOW:
                window_count += 1

        if window_count >= BURST_THRESHOLD_COUNT:
            bursts += 1

    # -----------------------------
    # SCORE
    # -----------------------------
    score = 0
    score += failed * FAILED_WEIGHT
    score += bursts * 20
    score += len(users) * MULTI_USER_WEIGHT
    score += success * SUCCESS_WEIGHT
    score += admin_fail * ADMIN_WEIGHT

    # -----------------------------
    # ATTACK TYPE
    # -----------------------------
    attack_type = "Unknown"

    if failed >= 5 and len(users) <= 1 and success == 0:
        attack_type = "Brute Force"

    elif failed >= 5 and len(users) >= 3:
        attack_type = "Credential Stuffing"

    elif failed >= 3 and len(users) >= 2:
        attack_type = "Password Spraying"

    elif success > 0 and failed >= 3:
        attack_type = "Possible Account Compromise"

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
    # CONFIDENCE
    # -----------------------------
    if score >= 80:
        confidence = "HIGH"
    elif score >= 50:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    ip_address = events[0][1]

    # -----------------------------
    # REPORT
    # -----------------------------
    report = {
        "ip": ip_address,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": confidence,
        "score": score,
        "failed_logins": failed,
        "successful_logins": success,
        "unique_users": len(users),
        "admin_failures": admin_fail,
        "bursts": bursts
    }

    # -----------------------------
    # OUTPUT (SOC STYLE)
    # -----------------------------
    print("\n==================================================")
    print("SOC SECURITY ALERT")
    print("==================================================")

    print(f"\nSEVERITY     : {severity}")
    print(f"ATTACK TYPE  : {attack_type}")
    print(f"CONFIDENCE   : {confidence}")
    print(f"IP ADDRESS   : {ip_address}")

    print("\nSUMMARY")
    print(f"- Failed logins: {failed}")
    print(f"- Success logins: {success}")
    print(f"- Users targeted: {len(users)}")
    print(f"- Bursts detected: {bursts}")

    print("\nTHREAT SCORE:", score)

    print("\n==================================================\n")

    # -----------------------------
    # JSON EXPORT
    # -----------------------------
    with open("alerts_output.json", "w") as f:
        json.dump(report, f, indent=4)


# -----------------------------
# MAIN
# -----------------------------
def run(file_path):
    with open(file_path, "r") as f:
        for line in f:
            parsed = parse_log(line)
            if parsed:
                logs[parsed[1]].append(parsed)

    for ip, events in logs.items():
        analyze_ip(events)


if __name__ == "__main__":
    run("auth_logs.txt")
