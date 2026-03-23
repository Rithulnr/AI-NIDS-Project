import numpy as np
from transformer_model import build_transformer
from phase2_neutralization import neutralize


# Load dataset (simulation)
X = np.load("X.npy")
y = np.load("y.npy")

# Build model
model = build_transformer(
    seq_len=X.shape[1],
    num_features=X.shape[2]
)

# Load trained weights
model.load_weights("model_weights.h5")

print("\n--- Runtime Detection + Neutralization ---")

# Simulate real-time detection
for i in range(14070, 14110):

    x_input = X[i:i+1]

    pred_current, pred_future = model.predict(x_input, verbose=0)

    current_attack = float(pred_current[0][0])
    future_risk = float(pred_future[0][0])

    entity_id = f"flow_{i}"

    action = neutralize(entity_id, future_risk)

    print(
        f"t={i} | "
        f"true={y[i]} | "
        f"current={current_attack:.3f} | "
        f"future={future_risk:.3f} | "
        f"action={action}"
    )