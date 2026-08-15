import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AISecurityAnalyzer:

    HIGH_RISK_PORTS = {23, 135, 139, 445}
    LARGE_PACKET_SIZE = 1500

    def __init__(self):

        self.scaler = StandardScaler()

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42
        )

    def analyze(self, packets, suspicious_packets=None):

        if suspicious_packets is None:
            suspicious_packets = []

        # =========================
        # NO TRAFFIC
        # =========================

        if not packets:

            return {
                "risk_level": "LOW",
                "anomalies": 0,
                "total_packets": 0,
                "anomaly_percentage": 0,
                "risk_score": 0,
                "message": "No traffic available for analysis.",
                "recommendation": "Start network capture first."
            }

        total_packets = len(packets)

        # =========================
        # BUILD AI FEATURES
        # =========================

        features = []

        for packet in packets:

            protocol = packet[2]
            source_port = packet[3]
            destination_port = packet[4]
            size = packet[5]

            # Protocol features
            tcp = 1 if protocol == "TCP" else 0
            udp = 1 if protocol == "UDP" else 0
            icmp = 1 if protocol == "ICMP" else 0

            # Convert ports safely
            try:
                source_port = int(source_port)
            except:
                source_port = 0

            try:
                destination_port = int(
                    destination_port
                )
            except:
                destination_port = 0

            # Security indicators
            high_risk_source = (
                1
                if source_port in self.HIGH_RISK_PORTS
                else 0
            )

            high_risk_destination = (
                1
                if destination_port in self.HIGH_RISK_PORTS
                else 0
            )

            large_packet = (
                1
                if size > self.LARGE_PACKET_SIZE
                else 0
            )

            unknown_protocol = (
                1
                if protocol not in [
                    "TCP",
                    "UDP",
                    "ICMP"
                ]
                else 0
            )

            # Log transform prevents very large
            # packet sizes from dominating the model
            log_size = np.log1p(size)

            # IMPORTANT:
            # Raw port numbers are NOT used as
            # numerical ML features.
            features.append([
                log_size,
                tcp,
                udp,
                icmp,
                high_risk_source,
                high_risk_destination,
                large_packet,
                unknown_protocol
            ])

        X = np.array(features)

        # =========================
        # MINIMUM DATA
        # =========================

        if len(X) < 30:

            return {
                "risk_level": "LOW",
                "anomalies": 0,
                "total_packets": total_packets,
                "anomaly_percentage": 0,
                "risk_score": 0,
                "message": (
                    "AI is collecting more traffic "
                    "for reliable analysis."
                ),
                "recommendation": (
                    "Continue network capture."
                )
            }

        # =========================
        # NORMALIZE FEATURES
        # =========================

        X_scaled = self.scaler.fit_transform(X)

        # =========================
        # AI ANOMALY DETECTION
        # =========================

        predictions = self.model.fit_predict(
            X_scaled
        )

        ml_anomaly_indices = set(
            np.where(predictions == -1)[0]
        )

        ml_anomalies = len(
            ml_anomaly_indices
        )

        # =========================
        # RULE-BASED EVENTS
        # =========================

        rule_anomaly_indices = set()

        high_risk_events = 0
        large_packet_events = 0
        unknown_protocol_events = 0

        for index, packet in enumerate(packets):

            protocol = packet[2]
            source_port = packet[3]
            destination_port = packet[4]
            size = packet[5]

            try:
                source_port = int(source_port)
            except:
                source_port = 0

            try:
                destination_port = int(
                    destination_port
                )
            except:
                destination_port = 0

            # High-risk ports
            if (
                source_port in self.HIGH_RISK_PORTS
                or
                destination_port in self.HIGH_RISK_PORTS
            ):

                high_risk_events += 1
                rule_anomaly_indices.add(index)

            # Large packets
            if size > self.LARGE_PACKET_SIZE:

                large_packet_events += 1
                rule_anomaly_indices.add(index)

            # Unknown protocol
            if protocol not in [
                "TCP",
                "UDP",
                "ICMP"
            ]:

                unknown_protocol_events += 1
                rule_anomaly_indices.add(index)

        # =========================
        # UNIQUE ANOMALIES
        # =========================

        all_anomaly_indices = (
            ml_anomaly_indices
            |
            rule_anomaly_indices
        )

        anomaly_count = len(
            all_anomaly_indices
        )

        anomaly_percentage = (
            anomaly_count / total_packets
        ) * 100

        # =========================
        # RISK SCORE
        # =========================

        ml_rate = (
            ml_anomalies / total_packets
        ) * 100

        high_risk_rate = (
            high_risk_events / total_packets
        ) * 100

        large_packet_rate = (
            large_packet_events / total_packets
        ) * 100

        unknown_rate = (
            unknown_protocol_events
            / total_packets
        ) * 100

        ml_score = min(
            ml_rate * 3,
            30
        )

        port_score = min(
            high_risk_rate * 3,
            30
        )

        large_packet_score = min(
            large_packet_rate * 2,
            25
        )

        unknown_score = min(
            unknown_rate * 2,
            15
        )

        risk_score = round(
            ml_score
            + port_score
            + large_packet_score
            + unknown_score,
            1
        )

        risk_score = min(
            risk_score,
            100
        )

        # =========================
        # RISK LEVEL
        # =========================

        if risk_score >= 70:

            risk_level = "HIGH"

        elif risk_score >= 35:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        # =========================
        # ANALYSIS MESSAGE
        # =========================

        reasons = []

        if ml_anomalies > 0:

            reasons.append(
                f"{ml_anomalies} ML anomalies"
            )

        if high_risk_events > 0:

            reasons.append(
                f"{high_risk_events} high-risk port events"
            )

        if large_packet_events > 0:

            reasons.append(
                f"{large_packet_events} large packets"
            )

        if unknown_protocol_events > 0:

            reasons.append(
                f"{unknown_protocol_events} unknown protocols"
            )

        if reasons:

            message = (
                "AI detected "
                + ", ".join(reasons)
                + "."
            )

        else:

            message = (
                "AI analysis found no significant "
                "security anomalies."
            )

        # =========================
        # RECOMMENDATION
        # =========================

        if risk_level == "HIGH":

            recommendation = (
                "Immediate investigation recommended. "
                "Review high-risk ports, abnormal packet "
                "sizes and unusual traffic patterns."
            )

        elif risk_level == "MEDIUM":

            recommendation = (
                "Monitor the detected anomalies and "
                "review suspicious ports and traffic "
                "patterns."
            )

        else:

            recommendation = (
                "Traffic pattern appears mostly normal. "
                "Continue monitoring for changes."
            )

        # =========================
        # FINAL RESULT
        # =========================

        return {

            "risk_level": risk_level,

            "anomalies": anomaly_count,

            "total_packets": total_packets,

            "anomaly_percentage": round(
                anomaly_percentage,
                2
            ),

            "risk_score": risk_score,

            "message": message,

            "recommendation": recommendation
        }