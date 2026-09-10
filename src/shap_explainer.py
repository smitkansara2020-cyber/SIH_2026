import joblib
import shap

from src.explanation_rules import get_security_explanation


MODEL_PATH = "models/live/live_random_forest.pkl"
PREPROCESSOR_PATH = "models/live/live_preprocessor.pkl"


model = joblib.load(MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)

explainer = shap.TreeExplainer(model)


def explain_prediction(flow_df, top_n=5):

    # Convert raw flow into RF input
    X_processed = preprocessor.transform(flow_df)

    # Calculate SHAP values
    shap_values = explainer.shap_values(
        X_processed
    )


    # Handle SHAP output formats
    if isinstance(shap_values, list):

        attack_shap = shap_values[1][0]

    elif shap_values.ndim == 3:

        attack_shap = shap_values[0, :, 1]

    else:

        attack_shap = shap_values[0]


    # Get processed feature names
    try:

        feature_names = (
            preprocessor.get_feature_names_out()
        )

    except Exception:

        feature_names = [
            f"feature_{i}"
            for i in range(
                X_processed.shape[1]
            )
        ]


    contributions = []


    for name, value in zip(
        feature_names,
        attack_shap
    ):

        value = float(value)

        clean_name = str(name)

        # Name used to find explanation rule
        rule_name = clean_name


        # Numerical features
        if clean_name.startswith(
            "remainder__"
        ):

            clean_name = clean_name.replace(
                "remainder__",
                ""
            )

            rule_name = clean_name


        # Protocol one-hot encoded features
        elif clean_name.startswith(
            "proto_encoder__proto_"
        ):

            protocol = clean_name.replace(
                "proto_encoder__proto_",
                ""
            )

            # Human-readable name
            clean_name = (
                f"proto = {protocol}"
            )

            # Rule lookup name
            rule_name = (
                f"proto_{protocol}"
            )


        security_info = (
            get_security_explanation(
                rule_name,
                value
            )
        )


        # Extra protection
        if security_info is None:

            security_info = {
                "cause": (
                    f"{clean_name} influenced "
                    "the model prediction."
                ),

                "why": (
                    "Its value differed from "
                    "patterns learned by the "
                    "intrusion detection model."
                ),

                "action": (
                    "Compare this feature with "
                    "normal network behaviour and "
                    "inspect the associated traffic."
                )
            }


        contributions.append({

            "feature":
                clean_name,

            "shap_value":
                value,

            "impact": (
                "increases risk"
                if value > 0
                else "decreases risk"
            ),

            "cause":
                security_info["cause"],

            "why":
                security_info["why"],

            "action":
                security_info["action"]
        })


    # Strongest SHAP contributions first
    contributions.sort(
        key=lambda x: abs(
            x["shap_value"]
        ),
        reverse=True
    )


    return contributions[:top_n]