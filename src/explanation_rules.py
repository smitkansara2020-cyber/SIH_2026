def get_security_explanation(
    feature,
    shap_value=None
):

    feature = feature.lower()

    rules = {

        "sload": {
            "cause": "High source traffic load",
            "why": (
                "The source transmitted data at a rate that "
                "contributed to a higher attack prediction."
            ),
            "action": (
                "Monitor the source for repeated bursts or "
                "unusually high outbound traffic."
            )
        },

        "dload": {
            "cause": "High destination traffic load",
            "why": (
                "The amount or rate of traffic received by the "
                "destination influenced the model prediction."
            ),
            "action": (
                "Check whether the destination normally receives "
                "this volume of traffic."
            )
        },

        "rate": {
            "cause": "Unusual packet rate",
            "why": (
                "The number of packets transmitted per second "
                "was important to the model decision."
            ),
            "action": (
                "Watch for repeated high-rate connections or "
                "automated connection attempts."
            )
        },

        "spkts": {
            "cause": "Source packet count",
            "why": (
                "The number of packets sent by the source "
                "contributed to the prediction."
            ),
            "action": (
                "Check whether the source repeatedly generates "
                "similar packet patterns."
            )
        },

        "dpkts": {
            "cause": "Destination packet count",
            "why": (
                "The number of packets returned by the destination "
                "affected the model prediction."
            ),
            "action": (
                "Compare the response pattern with normal traffic "
                "from the same service."
            )
        },

        "sbytes": {
            "cause": "Source data volume",
            "why": (
                "The amount of data sent by the source influenced "
                "the Random Forest prediction."
            ),
            "action": (
                "Check for unusually large uploads or repeated "
                "outbound transfers."
            )
        },

        "dbytes": {
            "cause": "Destination data volume",
            "why": (
                "The amount of data received from the destination "
                "contributed to the model decision."
            ),
            "action": (
                "Verify whether this download volume is expected."
            )
        },

        "sinpkt": {
            "cause": "Unusual source packet timing",
            "why": (
                "The timing between packets sent by the source "
                "differed from patterns learned during training."
            ),
            "action": (
                "Monitor for repeated automated or burst-like "
                "packet timing."
            )
        },

        "dinpkt": {
            "cause": "Unusual destination packet timing",
            "why": (
                "The timing between destination packets influenced "
                "the prediction."
            ),
            "action": (
                "Compare the response timing with normal connections "
                "to the same destination."
            )
        },

        "smean": {
            "cause": "Unusual average source packet size",
            "why": (
                "The average size of packets sent by the source "
                "contributed to the prediction."
            ),
            "action": (
                "Check whether similar packet sizes repeatedly appear "
                "from this source."
            )
        },

        "dmean": {
            "cause": "Unusual average destination packet size",
            "why": (
                "The average size of received packets influenced "
                "the prediction."
            ),
            "action": (
                "Compare packet sizes with normal application traffic."
            )
        },

        "dur": {
            "cause": "Unusual connection duration",
            "why": (
                "The duration of the network flow contributed "
                "to the model decision."
            ),
            "action": (
                "Check whether repeated unusually short or long "
                "connections are being created."
            )
        },

        "proto_udp": {
            "cause": "UDP traffic pattern",
            "why": (
                "Characteristics associated with UDP traffic "
                "contributed to the Random Forest prediction."
            ),
            "action": (
                "Check whether the traffic is expected DNS, streaming, "
                "multicast, discovery, or another legitimate UDP service."
            )
        },

        "proto_tcp": {
            "cause": "TCP traffic pattern",
            "why": (
                "Characteristics associated with TCP traffic "
                "contributed to the model prediction."
            ),
            "action": (
                "Check whether the connection matches a normal "
                "application or service."
            )
        }
    }

    if feature in rules:
        return rules[feature]

    if feature.startswith("proto_"):

        protocol = feature.replace(
            "proto_",
            ""
        ).upper()

        return {
            "cause": f"{protocol} protocol behavior",
            "why": (
                f"Traffic characteristics associated with {protocol} "
                "contributed to the Random Forest prediction."
            ),
            "action": (
                "Verify whether this protocol is expected for "
                "the current connection."
            )
        }

    return {
        "cause": "Unusual network characteristic",
        "why": (
            "This network feature influenced the Random Forest "
            "prediction."
        ),
        "action": (
            "Monitor the connection and compare it with normal "
            "traffic patterns."
        )
    }


def get_model_agreement(
    rf_probability,
    lstm_probability
):

    if lstm_probability is None:

        return {
            "level": "Unavailable",
            "message": (
                "The LSTM is still warming up, so the current "
                "assessment mainly reflects the Random Forest."
            )
        }

    difference = abs(
        rf_probability -
        lstm_probability
    )

    if difference < 0.10:

        return {
            "level": "High",
            "message": (
                "Random Forest and LSTM produced similar "
                "risk estimates."
            )
        }

    elif difference < 0.25:

        return {
            "level": "Moderate",
            "message": (
                "Random Forest and LSTM show some disagreement "
                "about this flow."
            )
        }

    else:

        return {
            "level": "Low",
            "message": (
                "Random Forest and LSTM disagree significantly. "
                "This alert should be interpreted carefully."
            )
        }


def get_risk_summary(
    risk_level,
    final_probability
):

    percentage = round(
        final_probability * 100,
        1
    )

    if risk_level == "HIGH RISK":

        return (
            f"SENTINALS assigned this flow a {percentage}% risk score. "
            "The traffic contains characteristics strongly associated "
            "with attack-like behavior in the trained models."
        )

    elif risk_level == "SUSPICIOUS":

        return (
            f"SENTINALS assigned this flow a {percentage}% risk score. "
            "Some traffic characteristics appear unusual, but this "
            "does not confirm that an attack occurred."
        )

    elif risk_level == "WARMING_UP":

        return (
            "The LSTM does not yet have enough recent flows to make "
            "a complete sequence-based prediction."
        )

    return (
        f"SENTINALS assigned this flow a {percentage}% risk score. "
        "The current traffic pattern is closer to traffic classified "
        "as normal by the models."
    )


def get_general_recommendation(
    risk_level,
    protocol
):

    protocol = str(protocol).lower()

    if risk_level == "HIGH RISK":

        return (
            "Investigate the source and destination, review repeated "
            "connections, and correlate this alert with additional "
            "security information before taking blocking action."
        )

    if risk_level == "SUSPICIOUS":

        if protocol == "udp":

            return (
                "Monitor for repeated similar UDP flows. Check whether "
                "the destination belongs to legitimate DNS, multicast, "
                "streaming, or network-discovery activity before "
                "treating it as malicious."
            )

        return (
            "Monitor the source for repeated similar behavior and "
            "correlate the alert with other network activity."
        )

    return (
        "No immediate action is required. Continue monitoring for "
        "changes or repeated unusual behavior."
    )