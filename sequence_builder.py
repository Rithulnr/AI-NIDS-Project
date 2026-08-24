import pandas as pd
import numpy as np

# ----------------------------
# CONFIG
# ----------------------------
DATA_PATH = "data/processed/unsw_nb15_clean.csv"
SEQUENCE_LENGTH = 20

FEATURE_COLUMNS = [
    "dur",
    "Spkts",
    "Dpkts",
    "sbytes",
    "dbytes",
    "smeansz",
    "dmeansz",
    "Sintpkt",
    "Dintpkt"
]

# ----------------------------
# LOAD DATA
# ----------------------------
print("Loading dataset (limited to 50k rows for speed)...")
df = pd.read_csv(DATA_PATH, low_memory=False, nrows=50000)

# Sort by start time (real temporal order)
df = df.sort_values(by="Stime")


# ----------------------------
# STRICT DATA CLEANING (CRITICAL)
# ----------------------------

# Keep only required columns
required_cols = FEATURE_COLUMNS + ["attack_cat", "srcip", "Stime"]
df = df[required_cols]

# Force numeric features
for col in FEATURE_COLUMNS:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Remove NaN / Inf
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(subset=FEATURE_COLUMNS, inplace=True)

# Map attack_cat
attack_mapping = {
    'Normal': 0, 'Fuzzers': 1, 'Analysis': 2, 'Backdoors': 3, 
    'DoS': 4, 'Exploits': 5, 'Generic': 6, 'Reconnaissance': 7, 
    'Shellcode': 8, 'Worms': 9
}

# Clean attack_cat
df["attack_cat"] = df["attack_cat"].fillna("Normal").astype(str).str.strip()
df["attack_cat"] = df["attack_cat"].replace("", "Normal")

df["Label"] = df["attack_cat"].map(attack_mapping)
df["Label"] = df["Label"].fillna(0).astype(int)

# Clip extreme values (VERY IMPORTANT for UNSW)
df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].clip(-10, 10)

# Scale features AFTER cleaning
from sklearn.preprocessing import StandardScaler
import joblib

scaler = StandardScaler()
df[FEATURE_COLUMNS] = scaler.fit_transform(df[FEATURE_COLUMNS])

joblib.dump(scaler, "scaler.pkl")
print("Saved StandardScaler to scaler.pkl")

# ----------------------------
# BUILD SEQUENCES
# ----------------------------
def build_sequences(df, seq_len):
    sequences = []
    labels = []

    grouped = df.groupby("srcip")

    for src_ip, group in grouped:
        features = group[FEATURE_COLUMNS].values
        targets = group["Label"].values

        if len(features) < seq_len:
            continue

        for i in range(len(features) - seq_len):
            seq = features[i:i + seq_len]
            label = targets[i + seq_len - 1]
            if np.isnan(seq).any() or np.isnan(label):
                continue
            sequences.append(seq)
            labels.append(label)

    return np.array(sequences), np.array(labels)

X, y = build_sequences(df, SEQUENCE_LENGTH)

# ----------------------------
# OUTPUT CHECK
# ----------------------------
print("Sequences shape:", X.shape)
print("Labels shape:", y.shape)

print("\nFirst sequence:")
print(X[0])

print("\nCorresponding label:")
print(y[0])

np.save("X.npy", X)
np.save("y.npy", y)
