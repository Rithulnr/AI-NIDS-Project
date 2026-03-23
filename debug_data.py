import numpy as np

X = np.load("X.npy")
y = np.load("y.npy")

print("X dtype:", X.dtype)
print("y dtype:", y.dtype)

print("X shape:", X.shape)
print("y shape:", y.shape)

print("Any NaN in X:", np.isnan(X).any())
print("Any Inf in X:", np.isinf(X).any())
print("Any NaN in y:", np.isnan(y).any())
print("Unique labels:", np.unique(y))

print("X min:", np.nanmin(X))
print("X max:", np.nanmax(X))
