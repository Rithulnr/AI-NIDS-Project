from flask import Flask, render_template, jsonify
import threading
import numpy as np
import time

import joblib
import os
import warnings

# Suppress sklearn warnings and TensorFlow logs that clutter the terminal
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import logging
logging.getLogger('tensorflow').setLevel(logging.ERROR)

from packet_sniffer import start_sniffer
from neutralization import neutralize
import multiprocessing

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
packet_timestamps = []

# -------------------------
# DETECTION ENGINE
# -------------------------
def detection_engine(q):
    from transformer_model import build_transformer
    import joblib
    import queue
    import numpy as np
    
    # Load model and scaler locally inside the thread to prevent the child sniffer process
    # from loading TensorFlow and crashing due to memory limits.
    model = build_transformer(seq_len=20, num_features=5)
    try:
        if os.path.exists("model_weights.weights.h5"):
            model.load_weights("model_weights.weights.h5")
        elif os.path.exists("model_weights.h5"):
            model.load_weights("model_weights.h5")
    except:
        pass

    scaler = None
    if os.path.exists("scaler.pkl"):
        scaler = joblib.load("scaler.pkl")

    buffers = {}

    while True:
        try:
            packet = q.get(timeout=0.1)
        except queue.Empty:
            continue

        # Only monitor demo server traffic
        if packet["src_port"] != 8000 and packet["dst_port"] != 8000:
            continue

        src_ip = packet["src_ip"]

        # -------------------------
        # FEATURE BUFFER
        # -------------------------
        if src_ip not in buffers:
            buffers[src_ip] = []

        feature = [
            packet["dur"],
            packet["Spkts"],
            packet["Dpkts"],
            packet["sbytes"],
            packet["dbytes"]
        ]

        buffers[src_ip].append(feature)
        print(f"Captured packet from {src_ip} ({len(buffers[src_ip])}/20)")

        if len(buffers[src_ip]) > 20:
            buffers[src_ip].pop(0)

        if len(buffers[src_ip]) < 20:
            continue

        # -------------------------
        # AI PREDICTION
        # -------------------------
        X_raw = np.array(buffers[src_ip], dtype=np.float32)
        # Match the clipping used during training
        X_raw = np.clip(X_raw, -10, 10)
        
        if scaler:
            X_scaled = scaler.transform(X_raw)
        else:
            X_scaled = X_raw

        X = X_scaled.reshape(1, 20, 5)

        pred_current, pred_future = model.predict(X, verbose=0)

        # --- Heuristic Packet Rate Tracker ---
        current_time = time.time()
        packet_timestamps.append(current_time)
        if len(packet_timestamps) > 100:
            packet_timestamps.pop(0)
        
        packet_rate = 0
        if len(packet_timestamps) == 100:
            time_diff = current_time - packet_timestamps[0]
            if time_diff > 0.001:
                packet_rate = 100 / time_diff

        # -------------------------
        # CLASSIFICATION (AI DRIVEN)
        # -------------------------
        attack_mapping_inv = {
            0: 'Normal', 1: 'Fuzzers', 2: 'Analysis', 3: 'Backdoors', 
            4: 'DoS', 5: 'Exploits', 6: 'Generic', 7: 'Reconnaissance', 
            8: 'Shellcode', 9: 'Worms'
        }

        pred_cat_idx = int(np.argmax(pred_current[0]))
        attack_type = attack_mapping_inv.get(pred_cat_idx, "Unknown")
        future_risk = float(pred_future[0][0])
        current_risk = float(pred_current[0][pred_cat_idx])
        
        # --- Robust Classification Logic ---
        # If AI is confident in an attack ( > 30% )
        if pred_cat_idx != 0 and current_risk > 0.30:
            label = "ATTACK"
            state.attack_count += 1
            risk = current_risk
        # If AI detects an attack but with low confidence, or high future risk
        elif (pred_cat_idx != 0 and current_risk > 0.30) or future_risk > 0.65:
            label = "SUSPICIOUS"
            state.suspicious_count += 1
            risk = max(current_risk, future_risk)
            if pred_cat_idx == 0: attack_type = "None"
        else:
            label = "NORMAL"
            state.normal_count += 1
            risk = future_risk
            attack_type = "None"

        # Fallback for basic DDoS testing using rate
        if packet_rate > 5 and label != "ATTACK":
             if label == "NORMAL": state.normal_count -= 1
             else: state.suspicious_count -= 1
             
             label = "ATTACK"
             attack_type = "DoS"
             risk = 0.99
             state.attack_count += 1

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
    multiprocessing.freeze_support()
    q = multiprocessing.Queue()

    p1 = multiprocessing.Process(target=start_sniffer, args=(q,), daemon=True)
    p1.start()
    
    t2 = threading.Thread(target=detection_engine, args=(q,), daemon=True)
    t2.start()

    from waitress import serve
    serve(app, host='127.0.0.1', port=5050)