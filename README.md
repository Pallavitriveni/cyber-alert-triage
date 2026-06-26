# Enterprise SOC Triage & Telemetry Hub

An enterprise-grade, secure Security Operations Center (SOC) analyst workspace designed to streamline threat detection, incident management, and real-time alert triage. This application simulates a live data pipeline pulling security telemetry into a centralized dashboard with persistent storage and an authenticated gatekeeper.

## 🚀 Live Deployment
Explore the live platform here: **[Insert Your Streamlit Cloud Link Here]**

---

## 🛡️ Key Features

*   **Secure Authentication Gate:** Implements session-state access controls ensuring only authorized security analysts can interact with the telemetry data.
*   **Live Telemetry Pipeline:** Aggregates and displays continuous mock SIEM alerts for rapid event triage.
*   **Persistent Data Core:** Utilizes an integrated SQLite database layer to maintain consistent data states across analysts' incident updates and priority overrides.
*   **Dynamic Visual Metrics:** Renders interactive charts that scale in real time based on active threat severity and categorical distribution.
*   **Automated Incident Reporting:** Features a one-click compliance engine that dynamically compiles incident tables into downloadable reports.

---

## 🏗️ Architecture & Data Flow

```text
[Telemetry Stream / JSON] ➔ [Pandas Engine / Data Modeling] ➔ [SQLite Database Store]
                                                                       │
[Authorized Analyst] ➔ [Secure Login Gate] ➔ [Streamlit UI Layer] 🖘 [Real-time Charts]

