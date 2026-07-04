from collections import defaultdict

# -----------------------------
# CONFIG
# -----------------------------
FAILED_WEIGHT = 10
BURST_WEIGHT = 20
MULTI_USER_WEIGHT = 15
SUCCESS_WEIGHT = 20
ADMIN_WEIGHT = 30

BURST_THRESHOLD_SECONDS = 3  # rapid activity window


# -----------------------------
# PARSER (FIXED FOR YOUR LOG FORMAT)
# -----------------------------
def parse_log(line):
    try:
        parts = line.strip().split()

        data = {}

        for p in parts:
            if "=" in p:
                key, value = p.split("=")
                data[key] = value

        time_str = data.get("time", "0:0:0")
        h, m, s = map(int, time_str.split(":"))
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

    # Burst detection
    timestamps.sort()
    bursts = 0

    for i in range(1, len(timestamps)):
        if timestamps[i] - timestamps[i - 1] <= BURST_THRESHOLD_SECONDS:
            bursts += 1

    # -----------------------------
    # SCORE
    # -----------------------------
    score = 0
    score += failed * FAILED_WEIGHT
    score += bursts * BURST_WEIGHT
    score += len(users) * MULTI_USER_WEIGHT
    score += success * SUCCESS_WEIGHT
    score += admin_fail * ADMIN_WEIGHT

    # -----------------------------
    # ATTACK CLASSIFICATION
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
        severity = "CRITICAL 🔴"
    elif score >= 60:
        severity = "HIGH 🟠"
    elif score >= 30:
        severity = "MEDIUM 🟡"
    else:
        severity = "LOW 🟢"

    # -----------------------------
    # CONFIDENCE
    # -----------------------------
    if score >= 80:
        confidence = "HIGH"
    elif score >= 50:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # -----------------------------
    # OUTPUT
    # -----------------------------
    ip_address = events[0][1]

    print("\n==================================================")
    print("SOC SECURITY ALERT")
    print("==================================================")

    print(f"\nIP ADDRESS   : {ip_address}")
    print(f"THREAT SCORE : {score}")
    print(f"SEVERITY     : {severity}")
    print(f"ATTACK TYPE  : {attack_type}")
    print(f"CONFIDENCE   : {confidence}")

    print("\n--------------------------------------------------")

    print("SUMMARY")
    print(f"- Failed logins: {failed}")
    print(f"- Successful logins: {success}")
    print(f"- Unique users: {len(users)}")
    print(f"- Admin failures: {admin_fail}")

    print("\n--------------------------------------------------")

    print("RECOMMENDED ACTIONS")

    if severity in ["HIGH 🟠", "CRITICAL 🔴"]:
        print("✓ Investigate immediately")
        print("✓ Review affected accounts")
        print("✓ Consider IP blocking")
    else:
        print("✓ Monitor activity")

    print("\n==================================================\n")


# -----------------------------
# MAIN
# -----------------------------
def run(file_path):
    with open(file_path, "r") as f:
        for line in f:
            parsed = parse_log(line)
            if parsed:
                t, ip, user, status = parsed
                logs[ip].append(parsed)

    for ip, events in logs.items():
        analyze_ip(events)


if __name__ == "__main__":
    run("auth_logs.txt")
