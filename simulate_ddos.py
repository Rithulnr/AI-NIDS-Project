import requests
import threading
import time

TARGET = "http://127.0.0.1:8000/data"

# simulate normal traffic first
print("Generating normal traffic...")

for i in range(20):
    try:
        requests.get(TARGET)
    except:
        pass
    time.sleep(0.3)

print("Normal traffic completed")

# activate IDS attack detection
try:
    requests.post("http://127.0.0.1:5000/start_attack")
except:
    pass

print("Starting DDoS simulation")

def attack():
    while True:
        try:
            requests.get(TARGET)
        except:
            pass

for i in range(300):
    threading.Thread(target=attack).start()