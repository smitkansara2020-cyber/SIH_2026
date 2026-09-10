import pandas as pd

from shap_explainer import explain_prediction


df = pd.read_csv("logs/live_detections.csv")

latest = df.iloc[-1]

flow_df = pd.DataFrame([{
    "dur": latest["dur"],
    "proto": latest["protocol"],
    "spkts": latest["spkts"],
    "dpkts": latest["dpkts"],
    "sbytes": latest["sbytes"],
    "dbytes": latest["dbytes"],
    "rate": latest["rate"],
    "sload": latest["sload"],
    "dload": latest["dload"],
    "sinpkt": latest["sinpkt"],
    "dinpkt": latest["dinpkt"],
    "smean": latest["smean"],
    "dmean": latest["dmean"]
}])


print("\nLatest flow:")

print(
    latest["src_ip"],
    "->",
    latest["dst_ip"]
)

print(
    "Protocol:",
    latest["protocol"]
)

print(
    "Risk:",
    latest["risk_level"]
)

print(
    "Final probability:",
    latest["final_probability"]
)


print("\nSHAP explanation:")

explanation = explain_prediction(
    flow_df,
    top_n=5
)

for item in explanation:
    print(item)