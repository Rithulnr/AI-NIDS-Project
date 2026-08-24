import numpy as np
from transformer_model import build_transformer


def create_future_risk_labels(y, horizon=200, buffer=20):
    y_future = np.zeros_like(y)
    for i in range(len(y)):
        start = i + buffer
        end = min(i + horizon, len(y))
        if start < end and np.any(y[start:end] != 0):
            y_future[i] = 1
    return y_future




# Load data
X = np.load("X.npy")
y = np.load("y.npy")

print("X shape:", X.shape)
print("y shape:", y.shape)

# Create labels
y_current = y
y_future = create_future_risk_labels(y, horizon=200)

print("Future-risk label distribution:", np.unique(y_future, return_counts=True))

# Build model
model = build_transformer(
    seq_len=X.shape[1],
    num_features=X.shape[2]
)

model.summary()

# Train
model.fit(
    X,
    {
        "current_attack": y_current,
        "future_risk": y_future
    },
    epochs=5,
    batch_size=256,
    validation_split=0.2
)
model.save_weights("model_weights.weights.h5")
print("Model weights saved")

attack_indices_all = np.where(y != 0)[0]
if len(attack_indices_all) > 0:
    attack_idx = attack_indices_all[0]
    print("First attack at index:", attack_idx)
else:
    attack_idx = 0

# ===== STEP 3: Verify evolving-threat prediction =====

start = max(0, attack_idx - 30)
end = attack_idx + 10

pred_current, pred_future = model.predict(X[start:end])

pred_current_labels = np.argmax(pred_current, axis=-1)
pred_future = pred_future.flatten()
y_true = y[start:end]

print("\n--- Evolving threat check around first attack ---")
for i in range(len(y_true)):
    print(
        f"t={start+i:05d} | "
        f"true_cat={y_true[i]} | "
        f"pred_cat={pred_current_labels[i]} | "
        f"future_risk={pred_future[i]:.3f}"
    )


# ===== Lead-time computation =====

threshold = 0.25
lead_times = []

attack_indices = attack_indices_all[:20]  # only first 20 attacks

for idx, attack_idx in enumerate(attack_indices):
    print(f"Processing attack {idx+1}/{len(attack_indices)}", end="\r")

    start = max(0, attack_idx - 200)
    end = attack_idx

    _, pred_future_window = model.predict(X[start:end], verbose=0)
    pred_future_window = pred_future_window.flatten()

    risk_indices = np.where(pred_future_window > threshold)[0]
    if len(risk_indices) > 0:
        lead = (end - start) - risk_indices[0]
        lead_times.append(lead)

print("\nLead Time Statistics")
print("--------------------")
print("Average lead time:", np.mean(lead_times))
print("Median lead time:", np.median(lead_times))
print("Max lead time:", np.max(lead_times))
print("Min lead time:", np.min(lead_times))


from sklearn.metrics import confusion_matrix

pred_current, _ = model.predict(X)
pred_labels = np.argmax(pred_current, axis=-1)

cm = confusion_matrix(y, pred_labels)

print("\nConfusion Matrix:")
print(cm)
