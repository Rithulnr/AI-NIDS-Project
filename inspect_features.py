import pandas as pd

features = pd.read_csv(
    "data/raw/NUSW-NB15_features.csv",
    encoding="latin1"
)
print(features.head(10))
print("\nTotal features:", features.shape[0])
