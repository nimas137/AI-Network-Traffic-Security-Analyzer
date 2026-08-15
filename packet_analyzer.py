from scapy.all import AsyncSniffer, IP

packets = []
sniffer = None
capture_running = False

# Suspicious traffic
suspicious_packets = []
reported_alerts = set()

# High-risk ports
HIGH_RISK_PORTS = {23, 135, 139, 445}

# Large packet threshold
LARGE_PACKET_SIZE = 1500


def packet_callback(packet):

    global suspicious_packets

    if IP not in packet:
        return

    # =========================
    # BASIC PACKET INFORMATION
    # =========================

    source = packet[IP].src
    destination = packet[IP].dst
    protocol_number = packet[IP].proto

    # Protocol detection
    if protocol_number == 6:
        protocol = "TCP"

    elif protocol_number == 17:
        protocol = "UDP"

    elif protocol_number == 1:
        protocol = "ICMP"

    else:
        protocol = str(protocol_number)

    # =========================
    # PORT INFORMATION
    # =========================

    if packet.haslayer("TCP"):

        source_port = packet["TCP"].sport
        destination_port = packet["TCP"].dport

    elif packet.haslayer("UDP"):

        source_port = packet["UDP"].sport
        destination_port = packet["UDP"].dport

    else:

        source_port = "-"
        destination_port = "-"

    # Packet size
    size = len(packet)

    # =========================
    # SAVE NORMAL PACKET
    # =========================

    packets.append((
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        size
    ))

    # =========================
    # SUSPICIOUS TRAFFIC
    # =========================

    suspicious = False
    reason = ""
    severity = "MEDIUM"

    # High-risk source port
    if (
        source_port != "-"
        and source_port in HIGH_RISK_PORTS
    ):

        suspicious = True

        reason = (
            f"High-risk source port {source_port}"
        )

        severity = "HIGH"

    # High-risk destination port
    elif (
        destination_port != "-"
        and destination_port in HIGH_RISK_PORTS
    ):

        suspicious = True

        reason = (
            f"High-risk destination port "
            f"{destination_port}"
        )

        severity = "HIGH"

    # Unknown protocol
    elif protocol not in [
        "TCP",
        "UDP",
        "ICMP"
    ]:

        suspicious = True

        reason = (
            f"Unknown protocol {protocol}"
        )

        severity = "MEDIUM"

    # =========================
    # LARGE PACKET DETECTION
    # =========================

    elif size > LARGE_PACKET_SIZE:

        suspicious = True

        reason = (
            f"Large packet detected: "
            f"{size} bytes"
        )

        severity = "WARNING"

    # =========================
    # SAVE SUSPICIOUS PACKET
    # =========================


# =========================
# SAVE SUSPICIOUS PACKET
# =========================
# =========================
# SAVE SUSPICIOUS PACKET
# =========================

    if suspicious:

        alert_key = (
            source,
            destination,
            protocol,
            reason
        )

        if alert_key not in reported_alerts:

            reported_alerts.add(alert_key)

            suspicious_packets.append({

                "source": source,
                "destination": destination,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "size": size,
                "reason": reason,
                "severity": severity

            })

# =========================
# START CAPTURE
# =========================

def start_capture():

    global sniffer
    global capture_running

    if capture_running:
        return

    try:

        sniffer = AsyncSniffer(
            prn=packet_callback,
            store=False
        )

        sniffer.start()

        capture_running = True

        print("Capture Started")

    except Exception as e:

        sniffer = None

        capture_running = False

        print("Capture Error:", e)


# =========================
# STOP CAPTURE
# =========================

def stop_capture():

    global sniffer
    global capture_running

    if not capture_running:
        return

    try:

        if sniffer is not None:

            sniffer.stop()

        print("Capture Stopped")

    except Exception as e:

        print("Stop Error:", e)

    finally:

        sniffer = None

        capture_running = False
