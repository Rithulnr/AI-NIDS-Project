import pandas as pd

df = pd.read_csv("data/processed/unsw_nb15_clean.csv")

print(df.head())
print("\nColumns:")
print(df.columns.tolist())
