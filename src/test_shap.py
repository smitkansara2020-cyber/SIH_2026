import pandas as pd

from shap_explainer import explain_prediction


test_flow = pd.DataFrame([{
    "dur": 0.05,
    "proto": "tcp",
    "spkts": 5,
    "dpkts": 4,
    "sbytes": 1000,
    "dbytes": 2500,
    "rate": 180,
    "sload": 160000,
    "dload": 400000,
    "sinpkt": 0.01,
    "dinpkt": 0.02,
    "smean": 200,
    "dmean": 625
}])


explanation = explain_prediction(test_flow)

for item in explanation:
    print(item)