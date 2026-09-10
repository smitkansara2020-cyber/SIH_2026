class FlowAggregator:

    def __init__(self):
        self.flows = {}


    def get_flow_key(self, packet_info):

        src = (
            packet_info["src_ip"],
            packet_info["src_port"]
        )

        dst = (
            packet_info["dst_ip"],
            packet_info["dst_port"]
        )

        if src <= dst:
            return (
                src,
                dst,
                packet_info["proto"]
            )

        return (
            dst,
            src,
            packet_info["proto"]
        )


    def update_flow(self, packet_info):

        key = self.get_flow_key(packet_info)


        # ---------------------------------
        # CREATE NEW FLOW
        # ---------------------------------

        if key not in self.flows:

            self.flows[key] = {

                "src_ip": packet_info["src_ip"],
                "dst_ip": packet_info["dst_ip"],

                "src_port": packet_info["src_port"],
                "dst_port": packet_info["dst_port"],

                "proto": packet_info["proto"],

                "start_time": packet_info["timestamp"],
                "last_time": packet_info["timestamp"],

                "spkts": 0,
                "dpkts": 0,

                "sbytes": 0,
                "dbytes": 0,

                "src_times": [],
                "dst_times": []
            }


        flow = self.flows[key]


        # ---------------------------------
        # DETERMINE PACKET DIRECTION
        # ---------------------------------

        is_source = (
            packet_info["src_ip"] == flow["src_ip"]
            and
            packet_info["src_port"] == flow["src_port"]
        )


        if is_source:

            flow["spkts"] += 1

            flow["sbytes"] += packet_info["size"]

            flow["src_times"].append(
                packet_info["timestamp"]
            )


        else:

            flow["dpkts"] += 1

            flow["dbytes"] += packet_info["size"]

            flow["dst_times"].append(
                packet_info["timestamp"]
            )


        flow["last_time"] = packet_info["timestamp"]


        # ---------------------------------
        # DURATION
        # ---------------------------------

        dur = (
            flow["last_time"]
            - flow["start_time"]
        )

        dur = max(dur, 0.000001)


        # ---------------------------------
        # PACKET RATE
        # ---------------------------------

        total_packets = (
            flow["spkts"]
            + flow["dpkts"]
        )

        rate = total_packets / dur


        # ---------------------------------
        # NETWORK LOAD
        # bits / second
        # ---------------------------------

        sload = (
            flow["sbytes"] * 8
        ) / dur

        dload = (
            flow["dbytes"] * 8
        ) / dur


        # ---------------------------------
        # AVERAGE PACKET SIZE
        # ---------------------------------

        smean = (
            flow["sbytes"] / flow["spkts"]
            if flow["spkts"] > 0
            else 0
        )

        dmean = (
            flow["dbytes"] / flow["dpkts"]
            if flow["dpkts"] > 0
            else 0
        )


        # ---------------------------------
        # INTER-PACKET TIME
        # ---------------------------------

        sinpkt = self.average_interval(
            flow["src_times"]
        )

        dinpkt = self.average_interval(
            flow["dst_times"]
        )


        # ---------------------------------
        # RETURN MODEL FEATURES
        # ---------------------------------

        return {

            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],

            "dur": dur,
            "proto": flow["proto"],

            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],

            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],

            "rate": rate,

            "sload": sload,
            "dload": dload,

            "sinpkt": sinpkt,
            "dinpkt": dinpkt,

            "smean": smean,
            "dmean": dmean
        }


    def average_interval(self, timestamps):

        if len(timestamps) < 2:
            return 0

        intervals = []

        for i in range(1, len(timestamps)):

            intervals.append(
                timestamps[i]
                - timestamps[i - 1]
            )

        return sum(intervals) / len(intervals)

    def build_features(self, flow):

        dur = max(
            flow["last_time"] - flow["start_time"],
            0.000001
        )

        total_packets = flow["spkts"] + flow["dpkts"]

        rate = total_packets / dur

        sload = (flow["sbytes"] * 8) / dur
        dload = (flow["dbytes"] * 8) / dur

        smean = (
            flow["sbytes"] / flow["spkts"]
            if flow["spkts"] > 0 else 0
        )

        dmean = (
            flow["dbytes"] / flow["dpkts"]
            if flow["dpkts"] > 0 else 0
        )

        sinpkt = self.average_interval(
            flow["src_times"]
        )

        dinpkt = self.average_interval(
            flow["dst_times"]
        )

        return {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],

            "dur": dur,
            "proto": flow["proto"],

            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],

            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],

            "rate": rate,

            "sload": sload,
            "dload": dload,

            "sinpkt": sinpkt,
            "dinpkt": dinpkt,

            "smean": smean,
            "dmean": dmean
    }
    def get_expired_flows(self, current_time, timeout=2.0):

        completed = []
        expired_keys = []

        for key, flow in self.flows.items():

            idle_time = current_time - flow["last_time"]

            if idle_time >= timeout:

                completed.append(
                    self.build_features(flow)
                )

                expired_keys.append(key)

        for key in expired_keys:
            del self.flows[key]

        return completed