from collections import defaultdict
from datetime import datetime

# -----------------------------
# CONFIG (tunable SOC rules)
# -----------------------------
FAILED_LOGIN_POINTS = 10
UNIQUE_USER_BONUS = 5
RAPID_ATTEMPT_BONUS = 10
VELOCITY_BONUS = 20

LOW_THRESHOLD = 30
MEDIUM_THRESHOLD = 60
HIGH_THRESHOLD = 90

# -----------------------------
# STORAGE
# -----------------------------
events = defaultdict(list)

def parse_time(t):
    return datetime.strptime(t, "%H:%M:%S")

# -----------------------------
# LOAD LOGS
# -----------------------------
with open("auth_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        if len(parts) < 4:
            continue

        try:
            user = parts[0].split("=")[1]
            ip = parts[1].split("=")[1]
            status = parts[2].split("=")[1]
            time = parse_time(parts[3].split("=")[1])
        except:
            continue

        events[ip].append((time, user, status))

# -----------------------------
# ANALYSIS ENGINE
# -----------------------------
for ip, logs in events.items():

    logs.sort(key=lambda x: x[0])

    score = 0
    failed_count = 0
    success_count = 0
    users = set()
    admin_failures = 0

    last_time = None

    # time tracking
    start_time = logs[0][0]
    end_time = logs[-1][0]

    for time, user, status in logs:

        users.add(user)

        if status == "fail":
            score += FAILED_LOGIN_POINTS
            failed_count += 1

            if user.lower() == "admin":
                admin_failures += 1

        else:
            success_count += 1

        # rapid activity detection
        if last_time:
            diff = (time - last_time).seconds
            if diff <= 2:
                score += RAPID_ATTEMPT_BONUS

        last_time = time

    # unique user behaviour
    if len(users) > 3:
        score += UNIQUE_USER_BONUS

    # -----------------------------
    # TIME / VELOCITY ANALYSIS
    # -----------------------------
    duration = (end_time - start_time).seconds
    if duration == 0:
        duration = 1

    event_rate = failed_count / duration

    if event_rate > 1:
        score += VELOCITY_BONUS

    # -----------------------------
    # SEVERITY CLASSIFICATION
    # -----------------------------
    if score >= HIGH_THRESHOLD:
        severity = "CRITICAL"
    elif score >= MEDIUM_THRESHOLD:
        severity = "HIGH"
    elif score >= LOW_THRESHOLD:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # -----------------------------
    # SOC SUMMARY
    # -----------------------------
    summary = []

    if failed_count:
        summary.append(f"{failed_count} failed login attempts")

    if success_count:
        summary.append(f"{success_count} successful logins")

    if len(users) > 1:
        summary.append(f"{len(users)} different users targeted")

    if admin_failures:
        summary.append(f"admin account targeted {admin_failures} times")

    summary.append(f"Activity duration: {duration} seconds")
    summary.append(f"Failed login rate: {round(event_rate, 2)} per second")

    # -----------------------------
    # OUTPUT REPORT
    # -----------------------------
    print("\n" + "=" * 55)
    print(f"IP ADDRESS: {ip}")
    print(f"THREAT SCORE: {score}")
    print(f"SEVERITY: {severity}")
    print("-" * 55)

    print("SUMMARY:")
    for line in summary:
        print(f"- {line}")

    print("\nDETAILS:")
    print(f"Failed logins: {failed_count}")
    print(f"Successful logins: {success_count}")
    print(f"Unique users: {len(users)}")
    print(f"Admin failures: {admin_failures}")
    print(f"Duration: {duration}s")
    print(f"Event rate: {round(event_rate, 2)} / sec")
