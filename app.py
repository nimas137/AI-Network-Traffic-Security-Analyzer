from flask import Flask, render_template, redirect, url_for, jsonify, send_file
import packet_analyzer
from collections import Counter
from ai_security import AISecurityAnalyzer

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from datetime import datetime
import os


app = Flask(__name__)

# =========================
# AI SECURITY ANALYZER
# =========================

ai_analyzer = AISecurityAnalyzer()


# =========================
# MAIN DASHBOARD
# =========================

@app.route("/")
def home():

    packets = packet_analyzer.packets
    suspicious_packets = packet_analyzer.suspicious_packets

    total_packets = len(packets)

    tcp_count = sum(
        1 for p in packets
        if p[2] == "TCP"
    )

    udp_count = sum(
        1 for p in packets
        if p[2] == "UDP"
    )

    icmp_count = sum(
        1 for p in packets
        if p[2] == "ICMP"
    )

    total_bytes = sum(
        p[5] for p in packets
    )

    capture_status = (
        "Running"
        if packet_analyzer.capture_running
        else "Stopped"
    )

    # =========================
    # TOP TALKERS
    # =========================

    source_ips = [
        p[0]
        for p in packets
    ]

    top_talkers = Counter(
        source_ips
    ).most_common(5)

    return render_template(
        "index.html",

        packets=packets,

        total_packets=total_packets,

        tcp_count=tcp_count,

        udp_count=udp_count,

        icmp_count=icmp_count,

        total_bytes=total_bytes,

        capture_status=capture_status,

        suspicious_packets=suspicious_packets,

        suspicious_count=len(
            suspicious_packets
        ),

        top_talkers=top_talkers
    )


# =========================
# START CAPTURE
# =========================

@app.route("/start")
def start():

    packet_analyzer.start_capture()

    return redirect(
        url_for("home")
    )


# =========================
# STOP CAPTURE
# =========================

@app.route("/stop")
def stop():

    packet_analyzer.stop_capture()

    return redirect(
        url_for("home")
    )


# =========================
# LIVE DATA
# =========================

@app.route("/live_data")
def live_data():

    packets = packet_analyzer.packets

    suspicious_packets = (
        packet_analyzer.suspicious_packets
    )

    total_packets = len(packets)

    tcp_count = sum(
        1 for p in packets
        if p[2] == "TCP"
    )

    udp_count = sum(
        1 for p in packets
        if p[2] == "UDP"
    )

    icmp_count = sum(
        1 for p in packets
        if p[2] == "ICMP"
    )

    total_bytes = sum(
        p[5] for p in packets
    )

    capture_status = (
        "Running"
        if packet_analyzer.capture_running
        else "Stopped"
    )

    # =========================
    # TOP TALKERS
    # =========================

    source_ips = [
        p[0]
        for p in packets
    ]

    top_talkers = Counter(
        source_ips
    ).most_common(5)

    # =========================
    # AI SECURITY ANALYSIS
    # =========================

    ai_result = ai_analyzer.analyze(
        packets,
        suspicious_packets
    )
    print("AI RESULT:", ai_result)

    # =========================
    # SEND LIVE DATA
    # =========================

    return jsonify({

        "packets": packets,

        "total_packets": total_packets,

        "tcp_count": tcp_count,

        "udp_count": udp_count,

        "icmp_count": icmp_count,

        "total_bytes": total_bytes,

        "capture_status": capture_status,

        "suspicious_packets": suspicious_packets,

        "suspicious_count": len(
            suspicious_packets
        ),

        "top_talkers": top_talkers,

        "ai_analysis": ai_result

    })


# =========================
# SECURITY PDF REPOR
# =========================

@app.route("/generate_report")
def generate_report():

    packets = packet_analyzer.packets

    suspicious_packets = (
        packet_analyzer.suspicious_packets
    )

    # =========================
    # REPORT FOLDER
    # =========================

    report_folder = "reports"

    if not os.path.exists(
        report_folder
    ):

        os.makedirs(
            report_folder
        )

    report_path = os.path.join(
        report_folder,
        "security_report.pdf"
    )

    # =========================
    # BASIC STATISTICS
    # =========================

    total_packets = len(packets)

    tcp_count = sum(
        1 for p in packets
        if p[2] == "TCP"
    )

    udp_count = sum(
        1 for p in packets
        if p[2] == "UDP"
    )

    icmp_count = sum(
        1 for p in packets
        if p[2] == "ICMP"
    )

    unknown_protocol_count = sum(
        1
        for p in suspicious_packets
        if "Unknown protocol"
        in p["reason"]
    )

    large_packet_count = sum(
        1
        for p in suspicious_packets
        if "Large packet"
        in p["reason"]
    )

    high_risk_count = sum(
        1
        for p in suspicious_packets
        if "High-risk"
        in p["reason"]
    )

    total_bytes = sum(
        p[5] for p in packets
    )

    # =========================
    # CREATE PDF
    # =========================

    document = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story = []

    # =========================
    # TITLE
    # =========================

    story.append(
        Paragraph(
            "Network Traffic Security Report",
            styles["Title"]
        )
    )

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "Generated: "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            styles["Normal"]
        )
    )

    story.append(
        Spacer(1, 20)
    )

    # =========================
    # SUMMARY
    # =========================

    story.append(
        Paragraph(
            "Security Summary",
            styles["Heading2"]
        )
    )

    summary_data = [

        [
            "Security Metric",
            "Value"
        ],

        [
            "Total Packets",
            str(total_packets)
        ],

        [
            "Suspicious Packets",
            str(len(suspicious_packets))
        ],

        [
            "TCP Packets",
            str(tcp_count)
        ],

        [
            "UDP Packets",
            str(udp_count)
        ],

        [
            "ICMP Packets",
            str(icmp_count)
        ],

        [
            "Unknown Protocols",
            str(unknown_protocol_count)
        ],

        [
            "Large Packets",
            str(large_packet_count)
        ],

        [
            "High-Risk Port Events",
            str(high_risk_count)
        ],

        [
            "Total Traffic",
            f"{total_bytes} bytes"
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            3.5 * inch,
            2 * inch
        ]
    )

    summary_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.darkblue
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "ALIGN",
                (1, 1),
                (-1, -1),
                "CENTER"
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, 0),
                8
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, 0),
                8
            )
        ])
    )

    story.append(
        summary_table
    )

    story.append(
        Spacer(1, 25)
    )

    # =========================
    # SUSPICIOUS TRAFFIC
    # =========================

    story.append(
        Paragraph(
            "Suspicious Traffic Details",
            styles["Heading2"]
        )
    )

    if suspicious_packets:

        suspicious_data = [

            [
                "Source",
                "Destination",
                "Protocol",
                "Size",
                "Reason",
                "Severity"
            ]
        ]

        for item in suspicious_packets:

            suspicious_data.append([

                str(
                    item["source"]
                ),

                str(
                    item["destination"]
                ),

                str(
                    item["protocol"]
                ),

                str(
                    item["size"]
                ),

                str(
                    item["reason"]
                ),

                str(
                    item["severity"]
                )

            ])

        suspicious_table = Table(

            suspicious_data,

            repeatRows=1,

            colWidths=[

                0.9 * inch,
                0.9 * inch,
                0.7 * inch,
                0.5 * inch,
                1.4 * inch,
                0.7 * inch

            ]
        )

        suspicious_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.darkred
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                )

            ])
        )

        story.append(
            suspicious_table
        )

    else:

        story.append(
            Paragraph(
                "No suspicious traffic detected.",
                styles["Normal"]
            )
        )

    story.append(
        Spacer(1, 25)
    )

    # =========================
    # RECOMMENDATIONS
    # =========================

    story.append(
        Paragraph(
            "Security Recommendations",
            styles["Heading2"]
        )
    )

    recommendations = [

        "Monitor unknown protocols for unusual network activity.",

        "Investigate traffic associated with high-risk ports.",

        "Review unusually large packets.",

        "Continue monitoring suspicious network traffic.",

        "Regularly analyze network security logs."

    ]

    for recommendation in recommendations:

        story.append(
            Paragraph(
                "• " + recommendation,
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 5)
        )

    # =========================
    # BUILD PDF
    # =========================

    document.build(
        story
    )

    return send_file(
        report_path,
        as_attachment=True
    )


# =========================
# RUN FLASK
# =========================

if __name__ == "__main__":

    app.run(
        debug=True,
        use_reloader=False,
    )
