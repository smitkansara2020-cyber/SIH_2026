import warnings
import argparse
import msvcrt
import sys
parser = argparse.ArgumentParser()

parser.add_argument(
    "--user-id",
    required=True,
    help="User ID whose network session is being monitored"
)

args = parser.parse_args()

USER_ID = str(args.user_id) 

warnings.filterwarnings(
    "ignore",
    message=".*sklearn.utils.parallel.delayed.*"
)

from live_detection import (
    predict_rf,
    add_flow_to_lstm_buffer,
    predict_lstm_from_buffer,
    combine_predictions,
    is_valid_flow
)
from scapy.all import sniff
import time
from feature_extraction import extract_packet_info
from flow_aggregator import FlowAggregator
import csv
import os
from datetime import datetime


aggregator = FlowAggregator()

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs",
    "users",
    USER_ID
)

os.makedirs(
    LOG_DIR,
    exist_ok=True
)

LOCK_FILE = os.path.join(
    LOG_DIR,
    "capture.lock"
)

lock_handle = open(LOCK_FILE, "a+")

lock_handle.seek(0)

if os.path.getsize(LOCK_FILE) == 0:
    lock_handle.write("1")
    lock_handle.flush()
lock_handle.seek(0)

try:
    msvcrt.locking(
        lock_handle.fileno(),
        msvcrt.LK_NBLCK,
        1
    )

except OSError:
    print(
        f"Monitoring already running for user {USER_ID}"
    )
    sys.exit(0)

LOG_FILE = os.path.join(
    LOG_DIR,
    "live_detections.csv"
)

def print_detection(flow, rf_result, lstm_result, final_result):

    print("\n" + "-" * 50)

    print(
        f"{flow['src_ip']}  →  {flow['dst_ip']}"
    )

    print(
        f"Protocol: {flow['proto'].upper()}"
    )

    print()

    print(
        f"RF Probability: {rf_result['rf_probability'] * 100:.2f}%"
    )

    if lstm_result["ready"]:

        print(
            f"LSTM Probability: "
            f"{lstm_result['lstm_probability'] * 100:.2f}%"
        )

        print(
            f"Final Risk: "
            f"{final_result['final_probability'] * 100:.2f}%"
        )

    else:

        print(
            f"LSTM: Warming up "
            f"({lstm_result['flows_collected']}/10 flows)"
        )

    print()

    print(
        f"Status: {final_result['risk_level']}"
    )

    print("-" * 50)

def log_detection(flow, rf_result, lstm_result, final_result):

    file_exists = os.path.exists(LOG_FILE)

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "src_ip",
                "dst_ip",
                "protocol",
                "dur",
                "spkts",
                "dpkts",
                "sbytes",
                "dbytes",
                "rate",
                "sload",
                "dload",
                "sinpkt",
                "dinpkt",
                "smean",
                "dmean",
                "rf_probability",
                "lstm_probability",
                "final_probability",
                "risk_level"
            ])

        lstm_probability = (
            lstm_result["lstm_probability"]
            if lstm_result["ready"]
            else ""
        )

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            flow["src_ip"],
            flow["dst_ip"],
            flow["proto"],

            flow["dur"],
            flow["spkts"],
            flow["dpkts"],
            flow["sbytes"],
            flow["dbytes"],

            flow["rate"],
            flow["sload"],
            flow["dload"],

            flow["sinpkt"],
            flow["dinpkt"],

            flow["smean"],
            flow["dmean"],

            rf_result["rf_probability"],
            lstm_probability,
            final_result["final_probability"],
            final_result["risk_level"]
        ])

def packet_callback(packet):

    info = extract_packet_info(packet)

    if info is None:
        return

    aggregator.update_flow(info)

    completed_flows = aggregator.get_expired_flows(
        info["timestamp"],
        timeout=2.0
    )

    for flow in completed_flows:

        if not is_valid_flow(flow):
            continue

        rf_result = predict_rf(flow)

        buffer_status = add_flow_to_lstm_buffer(flow)

        lstm_result = predict_lstm_from_buffer()

        final_result = combine_predictions(
            rf_result,
            lstm_result
        )

        # Save every completed flow immediately
        log_detection(
            flow,
            rf_result,
            lstm_result,
            final_result
        )

        print_detection(
            flow,
            rf_result,
            lstm_result,
            final_result    
        )


print("Starting live network analysis...")

sniff(
    prn=packet_callback,
    store=False
)

# Process flows still remaining after capture ends
remaining_flows = aggregator.get_expired_flows(
    time.time(),
    timeout=0
)

for flow in remaining_flows:

    if not is_valid_flow(flow):
        continue

    rf_result = predict_rf(flow)

    buffer_status = add_flow_to_lstm_buffer(flow)

    lstm_result = predict_lstm_from_buffer()

    final_result = combine_predictions(
        rf_result,
        lstm_result
    )
    
    log_detection(
    flow,
    rf_result,
    lstm_result,
    final_result
)

    print_detection(
    flow,
    rf_result,
    lstm_result,
    final_result
)