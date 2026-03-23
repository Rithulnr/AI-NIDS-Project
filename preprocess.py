import numpy as np

def create_future_risk_labels(y_raw, horizon=20):
    """
    y_raw: original binary labels (0/1)
    horizon: how far ahead to look
    """
    y_future = []
    for i in range(len(y_raw)):
        if i + horizon < len(y_raw) and 1 in y_raw[i+1:i+horizon]:
            y_future.append(1)
        else:
            y_future.append(0)
    return np.array(y_future)

def temporal_split(X, y_current, y_future, train_ratio=0.7, val_ratio=0.15):
    n = len(X)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))

    return (
        X[:train_end], y_current[:train_end], y_future[:train_end],
        X[train_end:val_end], y_current[train_end:val_end], y_future[train_end:val_end],
        X[val_end:], y_current[val_end:], y_future[val_end:]
    )

