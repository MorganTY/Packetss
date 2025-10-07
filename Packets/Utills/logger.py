import csv
import os

LOG_FILE = "Log/traffic.csv"

def log_packet(data):
    os.makedirs("Log", exist_ok=True)
    write_header = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(data)
