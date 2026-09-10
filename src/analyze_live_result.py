import pandas as pd

df = pd.read_csv("logs/live_detections.csv")

print("\nTotal flows:", len(df))

print("\nRisk counts:")
print(df["risk_level"].value_counts())

print("\nRisk percentages:")
print(
    df["risk_level"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)

print("\nFinal probability statistics:")
print(
    df["final_probability"]
    .describe()
)

print("\nRF probability statistics:")
print(
    df["rf_probability"]
    .describe()
)

# LSTM may contain empty values during warmup
lstm = pd.to_numeric(
    df["lstm_probability"],
    errors="coerce"
)

print("\nLSTM probability statistics:")
print(lstm.describe())


print("\nProbability ranges:")

ranges = [
    (0.0, 0.40),
    (0.40, 0.50),
    (0.50, 0.60),
    (0.60, 0.70),
    (0.70, 0.75),
    (0.75, 1.01)
]

for low, high in ranges:

    count = (
        (df["final_probability"] >= low)
        &
        (df["final_probability"] < high)
    ).sum()

    print(
        f"{low:.2f} - {high:.2f}: {count}"
    )