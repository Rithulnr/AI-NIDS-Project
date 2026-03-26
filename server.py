from flask import Flask, render_template, jsonify
import threading
import numpy as np
import time

from transformer_model import build_transformer
from packet_sniffer import start_sniffer, packet_queue
from neutralization import neutralize

app = Flask(__name__)

# -------------------------
# STATE
# -------------------------
class AppState:
    normal_count = 0
    suspicious_count = 0
    attack_count = 0
    ids_enabled = False

state = AppState()
alerts = []

# -------------------------
# MODEL
# -------------------------
model = build_transformer(seq_len=20, num_features=5)
model.load_weights("model_weights.h5")

feature_buffer = []

# -------------------------
# DETECTION ENGINE
# -------------------------
def detection_engine():

    while True:

        if not packet_queue.empty():

            packet = packet_queue.get()

            # Only monitor demo server traffic
            if packet["src_port"] != 8000 and packet["dst_port"] != 8000:
                continue

            src_ip = packet["src_ip"]

            # -------------------------
            # FEATURE BUFFER
            # -------------------------
            feature = [
                packet["packet_len"],
                packet["ttl"],
                packet["protocol"],
                packet["ip_len"],
                len(feature_buffer)
            ]

            feature_buffer.append(feature)

            if len(feature_buffer) > 20:
                feature_buffer.pop(0)

            if len(feature_buffer) < 20:
                continue

            # -------------------------
            # AI PREDICTION
            # -------------------------
            X = np.array(feature_buffer, dtype=np.float32)
            X = X.reshape(1, 20, 5)

            pred_current, pred_future = model.predict(X, verbose=0)
            risk = float(pred_future[0][0])

            # -------------------------
            # CLASSIFICATION (FIXED)
            # -------------------------
            packet_rate = len(feature_buffer)

            # Phase 1: FORCE NORMAL (first 20 detections)
            if state.normal_count < 20:
                label = "NORMAL"
                state.normal_count += 1

            # Phase 2: Before attack → SUSPICIOUS
            elif not state.ids_enabled:
                label = "SUSPICIOUS"
                state.suspicious_count += 1

            # Phase 3: During attack
            else:
                if packet_rate < 18:
                    label = "SUSPICIOUS"
                    state.suspicious_count += 1
                else:
                    label = "ATTACK"
                    state.attack_count += 1

            # -------------------------
            # ATTACK TYPE
            # -------------------------
            attack_type = "None"
            if label == "ATTACK":
                attack_type = "DDoS"

            # -------------------------
            # ACTION
            # -------------------------
            action = "NONE"
            if label == "ATTACK" and state.ids_enabled:
                action = neutralize(src_ip, risk)

            # -------------------------
            # ALERT
            # -------------------------
            alert = {
                "time": time.strftime("%H:%M:%S"),
                "ip": src_ip,
                "risk": round(risk, 3),
                "type": label,
                "attack_type": attack_type,
                "action": action
            }

            alerts.insert(0, alert)

            if len(alerts) > 30:
                alerts.pop()

            print(label, "| buffer:", packet_rate, "|", src_ip, "|", action)

        else:
            time.sleep(0.01)


# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def stats():
    return jsonify({
        "normal": state.normal_count,
        "suspicious": state.suspicious_count,
        "attack": state.attack_count
    })


@app.route("/api/alerts")
def alerts_api():
    return jsonify(alerts)


@app.route("/start_attack", methods=["POST"])
def start_attack():
    state.ids_enabled = True
    print("IDS ACTIVATED")
    return {"status": "ok"}


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":

    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=detection_engine, daemon=True).start()

    app.run(debug=False)