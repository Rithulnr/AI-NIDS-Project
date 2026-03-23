import pandas as pd

# Load UNSW feature schema
features = pd.read_csv(
    "data/raw/NUSW-NB15_features.csv",
    encoding="latin1"
)

column_names = features["Name"].tolist()
print("Number of features (schema):", len(column_names))

# Load traffic data WITHOUT headers
df = pd.read_csv(
    "data/raw/unsw_nb15.csv",
    header=None,
    low_memory=False
)

print("Original traffic columns:", df.shape[1])

# KEEP ONLY FIRST 49 COLUMNS (official UNSW features)
df = df.iloc[:, :len(column_names)]
print("Trimmed traffic columns:", df.shape[1])

# Assign correct column names
df.columns = column_names

# Save cleaned dataset
df.to_csv(
    "data/processed/unsw_nb15_clean.csv",
    index=False
)

print("✅ Clean dataset saved to data/processed/unsw_nb15_clean.csv")
