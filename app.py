
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

from analyzer import (
    analyze_logs,
    create_report,
    SUSPICIOUS_THRESHOLD,
    TIME_WINDOW_MINUTES,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cybersecurity Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_FILE = BASE_DIR / "sample_logs.txt"


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    [data-testid="stMetric"] {
        background-color: rgba(128, 128, 128, 0.06);
        border: 1px solid rgba(128, 128, 128, 0.20);
        padding: 16px;
        border-radius: 12px;
    }

    .main-title {
        font-size: 2.2rem;
        font-weight: 750;
        margin-bottom: 0;
    }

    .subtitle {
        color: #8b949e;
        margin-top: 4px;
        margin-bottom: 20px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ Cybersecurity Log Analyzer</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    'Security monitoring dashboard · Login event analysis'
    '</div>',
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR SETTINGS
# ============================================================

with st.sidebar:
    st.header("⚙️ Monitoring settings")

    log_path_input = st.text_input(
        "Log file path",
        value=str(DEFAULT_LOG_FILE),
        help="Path to the log file you are authorized to monitor.",
    )

    refresh_seconds = st.selectbox(
        "Refresh interval",
        options=[2, 5, 10, 30, 60],
        index=1,
        format_func=lambda value: f"Every {value} seconds",
    )

    st.divider()

    st.subheader("Detection rules")
    st.write(f"Failed-login threshold: **{SUSPICIOUS_THRESHOLD}**")
    st.write(f"Time window: **{TIME_WINDOW_MINUTES} minute(s)**")

    st.divider()

    st.caption("Educational security monitoring project.")
    st.info("Only analyze log files you are authorized to access.")


# ============================================================
# MONITORING DASHBOARD
# ============================================================

@st.fragment(run_every=refresh_seconds)
def monitoring_dashboard():

    # --------------------------------------------------------
    # LOAD LOG FILE
    # --------------------------------------------------------

    log_path = Path(log_path_input).expanduser()

    if not log_path.is_absolute():
        log_path = (BASE_DIR / log_path).resolve()

    st.subheader("📡 Live monitoring")

    if not log_path.exists():
        st.error(f"Log file not found: {log_path}")
        st.info(
            "Check the path in the sidebar. "
            "The default file is sample_logs.txt."
        )
        return

    if not log_path.is_file():
        st.error("The selected path is not a file.")
        return

    try:
        content = log_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        # Process complete lines. A final unfinished line is
        # ignored until its newline arrives.
        lines = content.splitlines(keepends=True)

        complete_lines = [
            line for line in lines
            if line.endswith(("\n", "\r"))
        ]

        # Also support a small file containing one complete
        # record without a terminating newline.
        if (
            content
            and not content.endswith(("\n", "\r"))
            and len(lines) == 1
        ):
            complete_lines = [content]

        results = analyze_logs(complete_lines)

    except OSError as error:
        st.error(f"Unable to read the log file: {error}")
        return

    st.caption(
        f"Monitoring: {log_path} · "
        f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # --------------------------------------------------------
    # KEY METRICS
    # --------------------------------------------------------

    total_col, success_col, failed_col, invalid_col = st.columns(4)

    total_col.metric(
        "Total events",
        results["total_events"],
    )

    success_col.metric(
        "Successful logins",
        results["successful_logins"],
    )

    failed_col.metric(
        "Failed logins",
        results["failed_logins"],
    )

    invalid_col.metric(
        "Invalid lines",
        results["invalid_lines"],
    )

    st.divider()

    # --------------------------------------------------------
    # SECURITY ALERTS
    # --------------------------------------------------------

    st.subheader("🚨 Security alerts")

    window_alerts = results["window_alerts"]
    suspicious_ips = results["suspicious_ips"]

    if window_alerts:
        st.error(
            f"REVIEW REQUIRED: {len(window_alerts)} "
            "repeated-failure pattern(s) detected within "
            f"{TIME_WINDOW_MINUTES} minute(s)."
        )

        for alert in window_alerts:
            st.warning(
                f"IP {alert['ip']} recorded {alert['count']} "
                f"failed attempts between {alert['start']} "
                f"and {alert['end']}."
            )

    elif suspicious_ips:
        st.warning(
            f"THRESHOLD ALERT: {len(suspicious_ips)} IP address(es) "
            "reached the failed-login threshold."
        )

    else:
        st.success("No repeated-failure alerts detected.")

    if suspicious_ips:
        with st.expander("View suspicious IP details"):
            suspicious_df = pd.DataFrame(
                [
                    {
                        "IP address": ip,
                        "Failed attempts": count,
                    }
                    for ip, count in sorted(
                        suspicious_ips.items(),
                        key=lambda item: (-item[1], item[0]),
                    )
                ]
            )

            st.dataframe(
                suspicious_df,
                width="stretch",
                hide_index=True,
            )

    st.caption(
        "Alerts indicate activity requiring review; "
        "they do not prove that an attack occurred."
    )

    st.divider()

    # --------------------------------------------------------
    # CHARTS
    # --------------------------------------------------------

    st.subheader("📊 Security analytics")

    events = results["events"]

    if events:
        chart_col1, chart_col2 = st.columns(2)

        # Login status distribution
        with chart_col1:
            st.markdown("#### Login status distribution")

            status_df = pd.DataFrame(
                {
                    "Status": ["Successful", "Failed"],
                    "Count": [
                        results["successful_logins"],
                        results["failed_logins"],
                    ],
                }
            ).set_index("Status")

            st.bar_chart(
                status_df,
                height=280,
            )

        # Failed attempts by IP
        with chart_col2:
            st.markdown("#### Failed attempts by IP")

            top_ips = results["failed_counts"].most_common(10)

            if top_ips:
                ip_chart_df = pd.DataFrame(
                    top_ips,
                    columns=["IP address", "Failed attempts"],
                ).set_index("IP address")

                st.bar_chart(
                    ip_chart_df,
                    height=280,
                )
            else:
                st.info("No failed login attempts to display.")

        # Login activity over time
        st.markdown("#### Login activity over time")

        timeline_df = pd.DataFrame(events)

        timeline_df["timestamp"] = pd.to_datetime(
            timeline_df["timestamp"]
        )

        timeline_df["Minute"] = (
            timeline_df["timestamp"].dt.floor("min")
        )

        timeline_df["Event"] = timeline_df["status"].map(
            {
                "SUCCESS": "Successful",
                "FAILED": "Failed",
            }
        )

        timeline_chart = (
            timeline_df.groupby(["Minute", "Event"])
            .size()
            .unstack(fill_value=0)
            .sort_index()
        )

        st.line_chart(
            timeline_chart,
            height=300,
        )

    else:
        st.info("Charts will appear when valid log events are available.")

    st.divider()

    # --------------------------------------------------------
    # FAILED ATTEMPTS TABLE
    # --------------------------------------------------------

    st.subheader("🌐 Failed attempts by IP")

    if results["failed_counts"]:
        ip_df = pd.DataFrame(
            [
                {
                    "IP address": ip,
                    "Failed attempts": count,
                    "Alert": (
                        "Threshold reached"
                        if ip in suspicious_ips
                        else "Below threshold"
                    ),
                }
                for ip, count in results["failed_counts"].most_common()
            ]
        )

        st.dataframe(
            ip_df,
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No failed login attempts found.")

    st.divider()

    # --------------------------------------------------------
    # EVENT LOG TABLE WITH FILTERS
    # --------------------------------------------------------

    st.subheader("📋 Login events")

    if events:
        events_df = pd.DataFrame(events)

        events_df["timestamp"] = pd.to_datetime(
            events_df["timestamp"]
        )

        filter_col, search_col = st.columns([1, 2])

        with filter_col:
            status_filter = st.selectbox(
                "Filter by status",
                options=["ALL", "SUCCESS", "FAILED"],
                key="event_status_filter",
            )

        with search_col:
            ip_search = st.text_input(
                "Search IP address",
                placeholder="Enter an IP address",
                key="event_ip_search",
            )

        filtered_df = events_df.copy()

        if status_filter != "ALL":
            filtered_df = filtered_df[
                filtered_df["status"] == status_filter
            ]

        if ip_search.strip():
            filtered_df = filtered_df[
                filtered_df["ip"].str.contains(
                    ip_search.strip(),
                    case=False,
                    regex=False,
                )
            ]

        display_df = filtered_df.copy()

        display_df["timestamp"] = (
            display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
        )

        display_df = display_df.sort_values(
            "timestamp",
            ascending=False,
        )

        st.caption(f"Showing {len(display_df)} matching event(s).")

        st.dataframe(
            display_df,
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "⬇️ Download filtered events as CSV",
            data=display_df.to_csv(index=False).encode("utf-8"),
            file_name="login_events.csv",
            mime="text/csv",
            key="download_events_csv",
        )

    else:
        st.info("No valid login events are available yet.")

    st.divider()

    # --------------------------------------------------------
    # REPORT EXPORT
    # --------------------------------------------------------

    st.subheader("📄 Export security report")

    report_text = create_report(results)

    st.download_button(
        "⬇️ Download text report",
        data=report_text.encode("utf-8"),
        file_name="security_report.txt",
        mime="text/plain",
        key="download_security_report",
    )

    with st.expander("Preview report"):
        st.code(
            report_text,
            language="text",
        )


# ============================================================
# START DASHBOARD
# ============================================================

monitoring_dashboard()
