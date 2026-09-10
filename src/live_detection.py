import os
import joblib
import pandas as pd
from collections import deque

import torch
import numpy as np

from lstm_model import LSTMModel

# Folder containing this file: SIH_1/src
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Project root: SIH_1
BASE_DIR = os.path.dirname(CURRENT_DIR)

# SIH_1/models/live
MODEL_DIR = os.path.join(
    BASE_DIR,
    "models",
    "live"
)

RF_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "live_random_forest.pkl"
)

PREPROCESSOR_PATH = os.path.join(
    MODEL_DIR,
    "live_preprocessor.pkl"
)

FEATURES_PATH = os.path.join(
    MODEL_DIR,
    "live_features.pkl"
)


print("Model directory:", MODEL_DIR)

rf_model = joblib.load(RF_MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)
LIVE_FEATURES = joblib.load(FEATURES_PATH)


def predict_rf(flow):

    model_input = {
        feature: flow[feature]
        for feature in LIVE_FEATURES
    }

    df = pd.DataFrame([model_input])

    processed = preprocessor.transform(df)

    probability = rf_model.predict_proba(processed)[0][1]

    prediction = int(probability >= 0.5)

    return {
        "prediction": prediction,
        "rf_probability": float(probability)
    }
# -----------------------------------------
# LSTM PATHS
# -----------------------------------------

LSTM_DIR = os.path.join(
    BASE_DIR,
    "deeplearn_models",
    "live"
)

LSTM_MODEL_PATH = os.path.join(
    LSTM_DIR,
    "live_lstm_model.pth"
)

LSTM_SCALER_PATH = os.path.join(
    LSTM_DIR,
    "live_lstm_scaler.pkl"
)

LSTM_FEATURES_PATH = os.path.join(
    LSTM_DIR,
    "live_lstm_features.pkl"
)

LSTM_CONFIG_PATH = os.path.join(
    LSTM_DIR,
    "live_lstm_config.pkl"
)

lstm_scaler = joblib.load(
    LSTM_SCALER_PATH
)

lstm_feature_columns = joblib.load(
    LSTM_FEATURES_PATH
)

lstm_config = joblib.load(
    LSTM_CONFIG_PATH
)

lstm_model = LSTMModel(
    input_size=lstm_config["input_size"],
    hidden_size=lstm_config["hidden_size"],
    num_layers=lstm_config["num_layers"]
)

lstm_model.load_state_dict(
    torch.load(
        LSTM_MODEL_PATH,
        map_location="cpu"
    )
)

lstm_model.eval()

sequence_length = lstm_config["sequence_length"]

flow_buffer = deque(
    maxlen=sequence_length
)

def prepare_lstm_flow(flow):

    # Keep the same 13 raw features used during LSTM training
    model_input = {
        feature: flow[feature]
        for feature in LIVE_FEATURES
    }

    # Convert one flow to DataFrame
    df = pd.DataFrame([model_input])

    # Encode proto (tcp, udp, etc.)
    df = pd.get_dummies(
        df,
        columns=["proto"],
        drop_first=False
    )

    # Make columns exactly match LSTM training columns
    df = df.reindex(
        columns=lstm_feature_columns,
        fill_value=0
    )

    # Apply the same scaler used during LSTM training
    scaled = lstm_scaler.transform(df)

    return scaled[0].astype(np.float32)

def add_flow_to_lstm_buffer(flow):

    processed_flow = prepare_lstm_flow(flow)

    flow_buffer.append(processed_flow)

    return {
        "buffer_size": len(flow_buffer),
        "required": sequence_length,
        "ready": len(flow_buffer) == sequence_length
    }
def predict_lstm_from_buffer():

    # LSTM cannot predict until 10 flows are available
    if len(flow_buffer) < sequence_length:
        return {
            "ready": False,
            "flows_collected": len(flow_buffer)
        }

    # Convert buffer into numpy array
    sequence = np.array(
        flow_buffer,
        dtype=np.float32
    )

    # Convert to PyTorch tensor
    sequence_tensor = torch.tensor(
        sequence,
        dtype=torch.float32
    )

    # Add batch dimension
    sequence_tensor = sequence_tensor.unsqueeze(0)

    # Prediction
    with torch.no_grad():

        output = lstm_model(sequence_tensor)

        probability = torch.sigmoid(output).item()

    prediction = int(
        probability >= lstm_config["threshold"]
    )

    return {
        "ready": True,
        "prediction": prediction,
        "lstm_probability": probability
    }
def combine_predictions(rf_result, lstm_result):

    rf_probability = rf_result["rf_probability"]

    # LSTM does not have 10 flows yet
    if not lstm_result["ready"]:

        return {
            "final_probability": rf_probability,
            "final_prediction": rf_result["prediction"],
            "risk_level": "WARMING_UP",
            "model_used": "Random Forest only"
        }

    lstm_probability = lstm_result["lstm_probability"]

    # Weighted combination
    final_probability = (
        0.75 * rf_probability
        +
        0.25 * lstm_probability
    )

    final_prediction = int(
        final_probability >= 0.5
    )

    if final_probability < 0.6:
        risk_level = "NORMAL"

    elif final_probability < 0.75:
        risk_level = "SUSPICIOUS"

    else:
        risk_level = "HIGH RISK"

    return {
        "final_probability": float(final_probability),
        "final_prediction": final_prediction,
        "risk_level": risk_level,
        "model_used": "RF + LSTM"
    }
def is_valid_flow(flow):

    total_packets = flow["spkts"] + flow["dpkts"]

    # Ignore single-packet flows
    if total_packets < 2:
        return False

    # Ignore unrealistically tiny duration flows
    if flow["dur"] < 0.001:
        return False

    return True