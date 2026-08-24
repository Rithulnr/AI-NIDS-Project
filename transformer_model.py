import tensorflow as tf

layers = tf.keras.layers
models = tf.keras.models


def build_transformer(seq_len, num_features):
    # ===== Input =====
    inputs = layers.Input(shape=(seq_len, num_features))

    # ===== Encoder =====
    x = layers.Dense(64)(inputs)

    x = layers.MultiHeadAttention(
        num_heads=4,
        key_dim=16
    )(x, x)

    x = layers.LayerNormalization()(x) # type: ignore

    ffn = layers.Dense(64, activation="relu")(x)
    ffn = layers.Dense(64)(ffn)

    x = layers.Add()([x, ffn])
    x = layers.LayerNormalization()(x)

    # ===== Global Pooling =====
    x = layers.GlobalAveragePooling1D()(x)

    # ===== Dual Heads =====
    current_attack = layers.Dense(
        10,
        activation="softmax",
        name="current_attack"
    )(x)

    future_risk = layers.Dense(
        1,
        activation="sigmoid",
        name="future_risk"
    )(x)

    # ===== Model =====
    model = models.Model(
        inputs=inputs,
        outputs=[current_attack, future_risk]
    )

    # ===== Compile =====
    model.compile(
        optimizer="adam",
        loss={
            "current_attack": "sparse_categorical_crossentropy",
            "future_risk": "binary_crossentropy"
        },
        loss_weights={
            "current_attack": 0.4,
            "future_risk": 0.6
        },
        metrics=["accuracy"]
    )

    return model
