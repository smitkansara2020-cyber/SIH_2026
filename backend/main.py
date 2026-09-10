from fastapi import FastAPI
import pandas as pd
import os
from fastapi import Query
from src.explanation_rules import (
    get_model_agreement,
    get_risk_summary,
    get_general_recommendation
)
from fastapi.middleware.cors import CORSMiddleware
from backend.database import (
    create_users_table,
    create_otp_table,
    get_db_connection
)
import threading
import subprocess
import sys
import pandas as pd
from backend.database import get_db_connection
from src.shap_explainer import explain_prediction
import traceback
from datetime import datetime, timedelta
from pydantic import BaseModel
from backend.database import get_db_connection
from backend.auth import (
    hash_password,
    verify_password,
    validate_password,
    generate_otp,
    hash_otp
)

from backend.otp_service import (
    send_email_otp,
    send_sms_otp
)

from backend.firewall_manager import (
    choose_remote_ip,
    block_ip,
    unblock_ip
)

class LoginRequest(BaseModel):
    email: str
    password: str

class SignupRequest(BaseModel):

    name: str
    mobile: str
    email: str
    password: str
    otp_method: str

class BlockFlowRequest(BaseModel):
    user_id: int
    flow_id: int

class OTPVerifyRequest(BaseModel):
    email: str
    otp: str

class UnblockIPRequest(BaseModel):
    user_id: int
    ip_address: str

def get_user_log_path(user_id):

    return os.path.join(
        BASE_DIR,
        "logs",
        "users",
        str(user_id),
        "live_detections.csv"
    )

def get_blocked_ip_path(user_id):

    folder = os.path.join(
        BASE_DIR,
        "logs",
        "users",
        str(user_id)
    )

    os.makedirs(
        folder,
        exist_ok=True
    )

    return os.path.join(
        folder,
        "blocked_ips.csv"
    )

app = FastAPI()
create_users_table()
create_otp_table()

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

LOG_FILE = os.path.join(
    BASE_DIR,
    "logs",
    "live_detections.csv"
)


@app.get("/")
def home():
    return {
        "message": "SIH Cybersecurity Backend Running"
    }


@app.get("/api/detections")
def get_detections(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return []

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index
    return df.to_dict(orient="records")


@app.get("/api/latest")
def get_latest_detection(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return {
            "message": "No detections available"
        }

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index

    if df.empty:
        return {
            "message": "No detections available"
        }

    return df.iloc[-1].to_dict()


@app.get("/api/alerts")
def get_alerts(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return []

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index

    if df.empty:
        return []

    alerts = df[
        df["risk_level"].isin(
            ["SUSPICIOUS", "HIGH RISK"]
        )
    ]

    return alerts.to_dict(orient="records")


@app.get("/api/status")
def get_status(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return {
            "system_status": "RUNNING",
            "total_detections": 0,
            "latest_risk": None
        }

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index
    if df.empty:
        return {
            "system_status": "RUNNING",
            "total_detections": 0,
            "latest_risk": None
        }

    latest_risk = df.iloc[-1]["risk_level"]

    return {
        "system_status": "RUNNING",
        "total_detections": len(df),
        "latest_risk": latest_risk
    }


@app.get("/api/stats")
def get_stats(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return {
            "total": 0,
            "normal": 0,
            "suspicious": 0,
            "high_risk": 0
        }

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index

    return {
        "total": len(df),

        "normal": int(
            (df["risk_level"] == "NORMAL").sum()
        ),

        "suspicious": int(
            (df["risk_level"] == "SUSPICIOUS").sum()
        ),

        "high_risk": int(
            (df["risk_level"] == "HIGH RISK").sum()
        )
    }


@app.get("/api/recent")
def get_recent_detections(
    user_id: int,
    limit: int = Query(default=10, ge=1, le=100)
):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return []

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index

    if df.empty:
        return []

    recent = df.tail(limit)

    return recent.to_dict(orient="records")


@app.get("/api/filter")
def filter_detections(
    user_id: int,
    risk_level: str = None,
    protocol: str = None
):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return []

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index

    if risk_level:
        df = df[
            df["risk_level"].str.upper()
            == risk_level.upper()
        ]

    if protocol:
        df = df[
            df["protocol"].str.lower()
            == protocol.lower()
        ]

    return df.to_dict(orient="records")

@app.get("/api/dashboard")
def dashboard(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):

        return {
            "total": 0,
            "normal": 0,
            "suspicious": 0,
            "high_risk": 0,
            "latest": None
        }

    df = pd.read_csv(log_path)
    df["flow_id"] = df.index
    if df.empty:

        return {
            "total": 0,
            "normal": 0,
            "suspicious": 0,
            "high_risk": 0,
            "latest": None
        }

    return {
        "total": len(df),

        "normal": int(
            (df["risk_level"] == "NORMAL").sum()
        ),

        "suspicious": int(
            (df["risk_level"] == "SUSPICIOUS").sum()
        ),

        "high_risk": int(
            (df["risk_level"] == "HIGH RISK").sum()
        ),

        "latest": df.iloc[-1].to_dict()
    }
@app.post("/api/signup")
def signup(user: SignupRequest):

    connection = get_db_connection()
    cursor = connection.cursor()

    email = user.email.strip().lower()
    mobile = user.mobile.strip()

    existing_user = cursor.execute(
        """
        SELECT * FROM users
        WHERE LOWER(TRIM(email)) = ?
        OR mobile = ?
        """,
        (
            email,
            mobile
        )
    ).fetchone()

    # Existing verified account
    if existing_user and existing_user["is_verified"] == 1:

        connection.close()

        return {
            "success": False,
            "message": "User already exists. Please login."
        }


    # Generate OTP
    otp = generate_otp()

    if user.otp_method == "email":

        send_email_otp(
            email,
            otp
        )

    elif user.otp_method == "mobile":

        send_sms_otp(
            mobile,
            otp
        )

    else:

        connection.close()

        return {
            "success": False,
            "message": "Invalid OTP method"
        }


    # Hash password
    password_hash = hash_password(
        user.password
    )


    # Brand-new user
    if existing_user is None:

        cursor.execute(
            """
            INSERT INTO users
            (
                name,
                mobile,
                email,
                password_hash,
                is_verified
            )
            VALUES (?, ?, ?, ?, 0)
            """,
            (
                user.name,
                mobile,
                email,
                password_hash
            )
        )

    # Existing but unverified user
    else:

        cursor.execute(
            """
            UPDATE users
            SET
                name = ?,
                mobile = ?,
                password_hash = ?
            WHERE id = ?
            """,
            (
                user.name,
                mobile,
                password_hash,
                existing_user["id"]
            )
        )


    # Save OTP
    otp_hash_value = hash_otp(otp)

    expires_at = (
        datetime.now()
        + timedelta(minutes=5)
    ).isoformat()

    cursor.execute(
        """
        INSERT OR REPLACE INTO otp_codes
        (
            email,
            otp_hash,
            expires_at
        )
        VALUES (?, ?, ?)
        """,
        (
            email,
            otp_hash_value,
            expires_at
        )
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": f"OTP sent successfully via {user.otp_method}"
    }

@app.post("/api/verify-otp")
def verify_otp(data: OTPVerifyRequest):

    connection = get_db_connection()
    cursor = connection.cursor()

    otp_record = cursor.execute(
        """
        SELECT * FROM otp_codes
        WHERE email = ?
        """,
        (data.email,)
    ).fetchone()

    if not otp_record:

        connection.close()

        return {
            "success": False,
            "message": "OTP not found"
        }

    if datetime.now() > datetime.fromisoformat(
        otp_record["expires_at"]
    ):

        connection.close()

        return {
            "success": False,
            "message": "OTP expired"
        }

    if hash_otp(data.otp) != otp_record["otp_hash"]:

        connection.close()

        return {
            "success": False,
            "message": "Invalid OTP"
        }

    cursor.execute(
        """
        UPDATE users
        SET is_verified = 1
        WHERE email = ?
        """,
        (data.email,)
    )

    cursor.execute(
        """
        DELETE FROM otp_codes
        WHERE email = ?
        """,
        (data.email,)
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "Account verified successfully"
    }
@app.post("/api/login")
def login(user: LoginRequest):

    connection = get_db_connection()
    cursor = connection.cursor()

    email = user.email.strip().lower()

    db_user = cursor.execute(
        """
        SELECT * FROM users
        WHERE LOWER(TRIM(email)) = ?
        """,
        (email,)
    ).fetchone()

    connection.close()

    if db_user is None:
        return {
            "success": False,
            "message": "Invalid email or password"
        }

    if not verify_password(
        user.password,
        db_user["password_hash"]
    ):
        return {
            "success": False,
            "message": "Invalid email or password"
        }

    if not db_user["is_verified"]:
        return {
            "success": False,
            "message": "Please verify your account first"
        }

    return {
        "success": True,
        "message": "Login successful",
        "user": {
            "id": db_user["id"],
            "name": db_user["name"],
            "mobile": db_user["mobile"],
            "email": db_user["email"]
        }
    }
@app.delete("/api/logs")
def delete_user_logs(user_id: int):

    log_path = get_user_log_path(user_id)

    if not os.path.exists(log_path):
        return {
            "success": True,
            "message": "No detection history found"
        }

    try:
        os.remove(log_path)

        return {
            "success": True,
            "message": "Detection history cleared successfully"
        }

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

    if not db_user:
        connection.close()

        return {
            "success": False,
            "message": "User not found"
        }

    if db_user["is_verified"] != 1:
        connection.close()

        return {
            "success": False,
            "message": "Account not verified"
        }

    if not verify_password(
        user.password,
        db_user["password_hash"]
    ):
        connection.close()

        return {
            "success": False,
            "message": "Incorrect password"
        }

    connection.close()

    return {
        "success": True,
        "message": "Login successful",
        "user": {
            "id": db_user["id"],
            "name": db_user["name"],
            "email": db_user["email"],
            "mobile": db_user["mobile"]
        }
    }


@app.get("/api/explain/latest")
def explain_latest(user_id: int):

    try:
        log_path = get_user_log_path(user_id)

        if not os.path.exists(log_path):
            return {
                "success": False,
                "message": "No detections available"
            }

        df = pd.read_csv(log_path)
        df["flow_id"] = df.index
        if df.empty:
            return {
                "success": False,
                "message": "No detections available"
            }

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

        explanation = explain_prediction(
            flow_df,
            top_n=5
        )
        rf_probability = float(
    latest["rf_probability"]
)

        lstm_probability = (
            float(latest["lstm_probability"])
            if pd.notna(latest["lstm_probability"])
            else None
        )

        final_probability = float(
            latest["final_probability"]
        )


        agreement = get_model_agreement(
            rf_probability,
            lstm_probability
        )


        summary = get_risk_summary(
            latest["risk_level"],
            final_probability
        )


        recommendation = get_general_recommendation(
            latest["risk_level"],
            latest["protocol"]
        )

        return {

    "success": True,

    "risk_level":
        latest["risk_level"],

    "final_probability":
        final_probability,

    "rf_probability":
        rf_probability,

    "lstm_probability":
        lstm_probability,

    "src_ip":
        latest["src_ip"],

    "dst_ip":
        latest["dst_ip"],

    "protocol":
        latest["protocol"],

    "summary":
        summary,

    "model_agreement":
        agreement,

    "recommendation":
        recommendation,

    "explanation":
        explanation,

    "shap_note": (
        "SHAP explains the Random Forest component of "
        "SENTINALS. The final risk score also includes "
        "the LSTM prediction."
    )
}

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

active_monitors = {}
monitor_lock = threading.Lock()

@app.post("/api/stop-monitoring")
def stop_monitoring(user_id: int):

    if user_id not in active_monitors:
        return {
            "success": True,
            "message": "No monitoring process running"
        }

    process = active_monitors[user_id]

    if process.poll() is None:
        process.terminate()

        try:
            process.wait(timeout=5)

        except subprocess.TimeoutExpired:
            process.kill()

    del active_monitors[user_id]

    return {
        "success": True,
        "message": "Monitoring stopped"
    }

@app.post("/api/start-monitoring")
def start_monitoring(user_id: int):

    with monitor_lock:

        # Already tracked and running
        if user_id in active_monitors:

            process = active_monitors[user_id]

            if process.poll() is None:
                return {
                    "success": True,
                    "message": "Monitoring already running",
                    "pid": process.pid
                }

            # Remove dead process
            active_monitors.pop(user_id, None)

        try:

            script_path = os.path.join(
                BASE_DIR,
                "src",
                "live_capture.py"
            )

            process = subprocess.Popen(
                [
                    sys.executable,
                    script_path,
                    "--user-id",
                    str(user_id)
                ],
                cwd=BASE_DIR
            )

            active_monitors[user_id] = process

            return {
                "success": True,
                "message": "Monitoring started",
                "pid": process.pid
            }

        except Exception as e:

            return {
                "success": False,
                "message": str(e)
            }

@app.get("/api/explain/{flow_id}")
def explain_detection(
    flow_id: int,
    user_id: int
):

    try:

        log_path = get_user_log_path(
            user_id
        )

        if not os.path.exists(log_path):
            return {
                "success": False,
                "message": "No detections available"
            }

        df = pd.read_csv(log_path)

        if df.empty:
            return {
                "success": False,
                "message": "No detections available"
            }

        if flow_id < 0 or flow_id >= len(df):
            return {
                "success": False,
                "message": "Detection not found"
            }

        flow = df.iloc[flow_id]

        flow_df = pd.DataFrame([{

            "dur": flow["dur"],
            "proto": flow["protocol"],

            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],

            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],

            "rate": flow["rate"],

            "sload": flow["sload"],
            "dload": flow["dload"],

            "sinpkt": flow["sinpkt"],
            "dinpkt": flow["dinpkt"],

            "smean": flow["smean"],
            "dmean": flow["dmean"]
        }])

        explanation = explain_prediction(
            flow_df,
            top_n=5
        )

        rf_probability = float(
            flow["rf_probability"]
        )

        lstm_probability = (
            float(flow["lstm_probability"])
            if pd.notna(
                flow["lstm_probability"]
            )
            else None
        )

        final_probability = float(
            flow["final_probability"]
        )

        agreement = get_model_agreement(
            rf_probability,
            lstm_probability
        )

        summary = get_risk_summary(
            flow["risk_level"],
            final_probability
        )

        recommendation = (
            get_general_recommendation(
                flow["risk_level"],
                flow["protocol"]
            )
        )

        return {

            "success": True,

            "flow_id":
                flow_id,

            "timestamp":
                flow["timestamp"],

            "src_ip":
                flow["src_ip"],

            "dst_ip":
                flow["dst_ip"],

            "protocol":
                flow["protocol"],

            "risk_level":
                flow["risk_level"],

            "rf_probability":
                rf_probability,

            "lstm_probability":
                lstm_probability,

            "final_probability":
                final_probability,

            "summary":
                summary,

            "model_agreement":
                agreement,

            "recommendation":
                recommendation,

            "explanation":
                explanation,

            "shap_note": (
                "SHAP explains the Random Forest "
                "component of SENTINALS. The final "
                "risk score also includes the LSTM."
            )
        }

    except Exception as e:

        print("\n===== SHAP ERROR =====")

        traceback.print_exc()

        print("======================\n")

        return {
            "success": False,
            "message": str(e)
        }

@app.post("/api/block-flow")
def block_flow(request: BlockFlowRequest):

    try:

        log_path = get_user_log_path(
            request.user_id
        )

        if not os.path.exists(log_path):

            return {
                "success": False,
                "message": "Detection log not found."
            }


        df = pd.read_csv(log_path)


        if (
            request.flow_id < 0
            or request.flow_id >= len(df)
        ):

            return {
                "success": False,
                "message": "Detection not found."
            }


        flow = df.iloc[
            request.flow_id
        ]


        risk_level = str(
            flow["risk_level"]
        )


        # Don't allow blocking from a NORMAL flow
        if risk_level not in [
            "SUSPICIOUS",
            "HIGH RISK"
        ]:

            return {
                "success": False,
                "message":
                    "Blocking is available only for suspicious or high-risk flows."
            }


        src_ip = str(
            flow["src_ip"]
        )

        dst_ip = str(
            flow["dst_ip"]
        )


        remote_ip = choose_remote_ip(
            src_ip,
            dst_ip
        )


        if remote_ip is None:

            return {
                "success": False,
                "message":
                    "No safe public remote IPv4 address was identified."
            }


        result = block_ip(
            remote_ip
        )








        if result["success"]:

            blocked_path = get_blocked_ip_path(
                request.user_id
            )

            new_entry = pd.DataFrame([{
                "ip_address": remote_ip,
                "blocked_at": pd.Timestamp.now(),
                "flow_id": request.flow_id,
                "risk_level": risk_level,
                "status": "BLOCKED"
            }])

            if os.path.exists(blocked_path):

                old_df = pd.read_csv(
                    blocked_path
                )

                # Avoid duplicate active entries
                already_blocked = (
                    (
                        old_df["ip_address"]
                        .astype(str)
                        == remote_ip
                    )
                    &
                    (
                        old_df["status"]
                        == "BLOCKED"
                    )
                ).any()

                if not already_blocked:

                    new_entry.to_csv(
                        blocked_path,
                        mode="a",
                        header=False,
                        index=False
                    )

            else:

                new_entry.to_csv(
                    blocked_path,
                    index=False
                )


            return {
                "success": True,
                "blocked_ip": remote_ip,
                "flow_id": request.flow_id,
                "message":
                    f"Threat blocked successfully: {remote_ip}"
            }


        return result


    except Exception as error:

        return {
            "success": False,
            "message": str(error)
        }

@app.get("/api/blocked-ips")
def get_blocked_ips(user_id: int):

    path = get_blocked_ip_path(
        user_id
    )

    if not os.path.exists(path):
        return []

    df = pd.read_csv(path)

    if df.empty:
        return []

    blocked = df[
        df["status"] == "BLOCKED"
    ]

    return blocked.to_dict(
        orient="records"
    )
@app.post("/api/unblock-ip")
def unblock_blocked_ip(
    request: UnblockIPRequest
):

    try:

        result = unblock_ip(
            request.ip_address
        )

        if not result["success"]:
            return result


        path = get_blocked_ip_path(
            request.user_id
        )


        if os.path.exists(path):

            df = pd.read_csv(path)

            mask = (
                df["ip_address"]
                .astype(str)
                == request.ip_address
            )

            df.loc[
                mask,
                "status"
            ] = "UNBLOCKED"

            df.to_csv(
                path,
                index=False
            )


        return {
            "success": True,
            "ip_address":
                request.ip_address,
            "message":
                "IP successfully unblocked."
        }


    except Exception as error:

        return {
            "success": False,
            "message": str(error)
        }