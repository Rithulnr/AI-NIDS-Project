import requests
import threading
import time

TARGET = "http://127.0.0.1:8000/data"

# simulate normal traffic first
print("Generating normal traffic...")

for i in range(100):
    try:
        requests.get(TARGET)
    except:
        pass
    time.sleep(0.1)

print("Normal traffic completed")
print("Starting DDoS simulation")

def attack():
    while True:
        try:
            requests.get(TARGET, timeout=1)
        except:
            pass
        time.sleep(0.1)

for i in range(10):
    threading.Thread(target=attack, daemon=True).start()

while True:
    time.sleep(1)