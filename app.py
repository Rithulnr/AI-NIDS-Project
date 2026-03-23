from flask import Flask, request, render_template, session, redirect
import time
import numpy as np
from collections import deque

from transformer_model import build_transformer
from phase2_neutralization import neutralize

app = Flask(__name__)
app.secret_key = "demo_key"

model = build_transformer(10, 5)
model.load_weights("model_weights.h5")

request_times = deque(maxlen=50)

def extract_features():
    now = time.time()
    request_times.append(now)

    rate = len(request_times) / max(request_times[-1] - request_times[0], 0.001)
    burst = rate / 20
    gap_var = np.var(np.diff(request_times)) if len(request_times) > 2 else 0
    entropy = len(set(request_times)) / len(request_times)
    instability = rate / 30

    X = np.zeros((1, 10, 5))
    X[:, :, :] = [rate, burst, gap_var, entropy, instability]
    return X

@app.before_request
def detect_attack():
    X = extract_features()
    _, future = model.predict(X, verbose=0)
    risk = float(future[0][0])
    action = neutralize(request.remote_addr, risk)

    if action == "TEMPORARY_ISOLATION":
        return render_template("blocked.html", risk=risk)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["POST"])
def login():
    return "Login attempt recorded"


@app.route("/simulate_attack")
def simulate_attack():
    # Simulate burst traffic (bot-like behavior)
    for _ in range(25):
        extract_features()   # rapidly updates traffic behavior
        _, future = model.predict(extract_features(), verbose=0)
        risk = float(future[0][0])
        action = neutralize("simulated_attacker", risk)

        if action == "TEMPORARY_ISOLATION":
            return render_template("blocked.html", risk=risk)

    return "Attack simulation completed, but no block triggered."


if __name__ == "__main__":
    app.run(debug=True)
