import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import random
from datetime import datetime, timedelta
import time
import jwt

# Page config
st.set_page_config(
    page_title="Safebloq - Zero Trust Security",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark/light theme and modern styling
def load_css():
    theme = st.session_state.get('theme', 'dark')
    
    if theme == 'dark':
        bg_color = "#0e1117"
        text_color = "#fafafa"
        card_bg = "#262730"
        border_color = "#4a4a4a"
        sidebar_bg = "#1e1e1e"
        input_bg = "#2d2d2d"
        plotly_bg = "rgba(38, 39, 48, 0.8)"
    else:
        bg_color = "#ffffff"
        text_color = "#262626"
        card_bg = "#f8f9fa"
        border_color = "#e0e0e0"
        sidebar_bg = "#f0f2f6"
        input_bg = "#ffffff"
        plotly_bg = "rgba(248, 249, 250, 0.8)"
    
    st.markdown(f"""
    <style>
    /* Global theme styles */
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
    }}
    
    /* Sidebar styling */
    .css-1d391kg {{
        background-color: {sidebar_bg};
    }}
    
    /* Main content area */
    .main > div {{
        padding-top: 2rem;
        background-color: {bg_color};
    }}
    
    /* Header styling */
    .safebloq-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 0;
        border-bottom: 2px solid {border_color};
        margin-bottom: 2rem;
        background-color: {card_bg};
        border-radius: 10px;
        padding: 1.5rem;
    }}
    
    .safebloq-logo {{
        font-size: 2rem;
        font-weight: bold;
        color: #2E86AB;
    }}
    
    /* Security score styling */
    .security-score-container {{
        text-align: center;
        padding: 2rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 15px;
        color: white;
        margin-bottom: 2rem;
    }}
    
    .security-score {{
        font-size: 3rem;
        font-weight: bold;
        margin: 1rem 0;
    }}
    
    /* Card styling */
    .metric-card {{
        background-color: {card_bg};
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid {border_color};
        margin-bottom: 1rem;
    }}
    
    /* Alert styling */
    .alert-critical {{
        background-color: #ff4757;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }}
    
    .alert-warning {{
        background-color: #ffa726;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }}
    
    .alert-info {{
        background-color: #42a5f5;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }}
    
    /* Device status styling */
    .device-secure {{
        color: #4caf50;
        font-weight: bold;
    }}
    
    .device-risk {{
        color: #ff5722;
        font-weight: bold;
    }}
    
    .device-warning {{
        color: #ff9800;
        font-weight: bold;
    }}
    
    /* Container styling */
    .device-container {{
        background-color: {card_bg};
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid {border_color};
        margin-bottom: 0.5rem;
    }}
    
    /* Input styling */
    .stTextInput > div > div > input {{
        background-color: {input_bg};
        color: {text_color};
        border: 1px solid {border_color};
    }}
    
    .stSelectbox > div > div > select {{
        background-color: {input_bg};
        color: {text_color};
        border: 1px solid {border_color};
    }}
    
    /* Plotly chart background */
    .js-plotly-plot {{
        background-color: {plotly_bg} !important;
    }}
    
    /* Theme toggle button */
    .theme-toggle {{
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        cursor: pointer;
        font-weight: bold;
    }}
    
    /* Expander styling */
    .streamlit-expanderHeader {{
        background-color: {card_bg};
        border: 1px solid {border_color};
        border-radius: 5px;
    }}
    
    /* Tab styling */
    .stTabs > div > div > div > div {{
        background-color: {card_bg};
        border: 1px solid {border_color};
        border-radius: 5px;
    }}
    
    /* Mobile responsive */
    @media (max-width: 768px) {{
        .safebloq-header {{
            flex-direction: column;
            text-align: center;
        }}
        
        .security-score {{
            font-size: 2rem;
        }}
    }}
    </style>
    """, unsafe_allow_html=True)

# Initialize session state
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'

if 'security_score' not in st.session_state:
    st.session_state.security_score = random.randint(75, 95)

# Generate sample data
@st.cache_data(ttl=300)  # Cache for 5 minutes
def generate_threat_data():
    dates = [datetime.now() - timedelta(days=x) for x in range(30, 0, -1)]
    threats = {
        'Date': dates,
        'Malware': [random.randint(0, 5) for _ in range(30)],
        'Phishing': [random.randint(0, 8) for _ in range(30)],
        'Intrusion': [random.randint(0, 3) for _ in range(30)],
        'DDoS': [random.randint(0, 2) for _ in range(30)]
    }
    return pd.DataFrame(threats)

@st.cache_data(ttl=300)
def generate_device_data():
    devices = []
    device_types = ['Laptop', 'Desktop', 'Mobile', 'Tablet', 'Server']
    statuses = ['Secure', 'At Risk', 'Warning', 'Updating']
    
    for i in range(20):
        devices.append({
            'Device': f"{random.choice(device_types)}-{i+1:03d}",
            'User': f"user{i+1}@company.com",
            'Status': random.choice(statuses),
            'Last Seen': datetime.now() - timedelta(hours=random.randint(0, 48)),
            'OS': random.choice(['Windows 11', 'macOS 13', 'Ubuntu 22.04', 'iOS 16', 'Android 13']),
            'Risk Score': random.randint(10, 90)
        })
    
    return pd.DataFrame(devices)

@st.cache_data(ttl=60)  # Cache for 1 minute for live alerts
def generate_live_alerts():
    alert_types = ['Malware Detected', 'Unsafe Device', 'Phishing Attempt', 'Outbound Denial', 'Login Anomaly']
    severities = ['Critical', 'Warning', 'Info']
    
    alerts = []
    for i in range(8):
        alerts.append({
            'Time': datetime.now() - timedelta(minutes=random.randint(0, 120)),
            'Alert': random.choice(alert_types),
            'Severity': random.choice(severities),
            'Device': f"Device-{random.randint(1, 50):03d}",
            'Status': random.choice(['Active', 'Investigating', 'Resolved'])
        })
    
    return sorted(alerts, key=lambda x: x['Time'], reverse=True)

# Security score gauge
def create_security_gauge(score):
    theme = st.session_state.get('theme', 'dark')
    
    if theme == 'dark':
        paper_bg = "rgba(38, 39, 48, 0.8)"
        plot_bg = "rgba(38, 39, 48, 0.8)"
        font_color = "#fafafa"
    else:
        paper_bg = "rgba(248, 249, 250, 0.8)"
        plot_bg = "rgba(248, 249, 250, 0.8)"
        font_color = "#262626"
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Security Score", 'font': {'color': font_color}},
        delta = {'reference': 85},
        gauge = {
            'axis': {'range': [None, 100], 'tickcolor': font_color, 'tickfont': {'color': font_color}},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 50], 'color': "lightgray"},
                {'range': [50, 80], 'color': "yellow"},
                {'range': [80, 100], 'color': "lightgreen"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor=paper_bg,
        plot_bgcolor=plot_bg,
        font=dict(color=font_color)
    )
    
    return fig

# Threat trends chart
def create_threat_trends():
    df = generate_threat_data()
    theme = st.session_state.get('theme', 'dark')
    
    if theme == 'dark':
        paper_bg = "rgba(38, 39, 48, 0.8)"
        plot_bg = "rgba(38, 39, 48, 0.8)"
        font_color = "#fafafa"
    else:
        paper_bg = "rgba(248, 249, 250, 0.8)"
        plot_bg = "rgba(248, 249, 250, 0.8)"
        font_color = "#262626"
    
    fig = go.Figure()
    
    colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
    threat_types = ['Malware', 'Phishing', 'Intrusion', 'DDoS']
    
    for i, threat_type in enumerate(threat_types):
        fig.add_trace(go.Scatter(
            x=df['Date'],
            y=df[threat_type],
            mode='lines+markers',
            name=threat_type,
            line=dict(color=colors[i], width=3),
            marker=dict(size=6)
        ))
    
    fig.update_layout(
        title="Threat Trends (Last 30 Days)",
        xaxis_title="Date",
        yaxis_title="Threats Detected",
        height=400,
        hovermode='x unified',
        paper_bgcolor=paper_bg,
        plot_bgcolor=plot_bg,
        font=dict(color=font_color),
        xaxis=dict(color=font_color),
        yaxis=dict(color=font_color)
    )
    
    return fig

# Main app
def main():
    load_css()
    
    # Header
    st.markdown(f"""
    <div class="safebloq-header">
        <div class="safebloq-logo">🔐 Safebloq</div>
        <div>Zero Trust Security Platform</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation
    with st.sidebar:
        st.title("Navigation")
        page = st.selectbox(
            "Select Page",
            ["Dashboard", "Devices", "Reports", "Team", "Support"]
        )
        
        st.divider()
        
        # Theme toggle
        current_theme = st.session_state.get('theme', 'dark')
        theme_emoji = "☀️" if current_theme == 'dark' else "🌙"
        theme_text = "Light Mode" if current_theme == 'dark' else "Dark Mode"
        
        if st.button(f"{theme_emoji} {theme_text}"):
            st.session_state.theme = 'light' if st.session_state.theme == 'dark' else 'dark'
            st.rerun()
        
        st.divider()
        
        # Quick stats
        st.subheader("Quick Stats")
        st.metric("Active Devices", "23", "+2")
        st.metric("Threats Blocked", "156", "+12")
        st.metric("Compliance Score", "94%", "+1%")
    
    # Main content based on selected page
    if page == "Dashboard":
        show_dashboard()
    elif page == "Devices":
        show_devices()
    elif page == "Reports":
        show_reports()
    elif page == "Team":
        show_team()
    elif page == "Support":
        show_support()

def show_dashboard():
    st.title("Security Dashboard")
    
    # Top row - Security Score and key metrics
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    
    with col1:
        st.plotly_chart(create_security_gauge(st.session_state.security_score), use_container_width=True)
    
    with col2:
        st.metric("Active Threats", "3", "-2")
        st.metric("Devices Online", "23/25", "+1")
    
    with col3:
        st.metric("Blocked Attacks", "47", "+8")
        st.metric("Compliance", "94%", "+2%")
    
    with col4:
        st.metric("Response Time", "2.3s", "-0.5s")
        st.metric("Uptime", "99.9%", "0%")
    
    st.divider()
    
    # Second row - Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(create_threat_trends(), use_container_width=True)
    
    with col2:
        st.subheader("Live Security Alerts")
        alerts = generate_live_alerts()
        
        for alert in alerts[:6]:  # Show top 6 alerts
            severity_class = f"alert-{alert['Severity'].lower()}"
            time_str = alert['Time'].strftime("%H:%M")
            
            st.markdown(f"""
            <div class="{severity_class}">
                <strong>{time_str}</strong> - {alert['Alert']}<br>
                Device: {alert['Device']} | Status: {alert['Status']}
            </div>
            """, unsafe_allow_html=True)
    
    # Auto-refresh button
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

def show_devices():
    st.title("Device Management")
    
    # Add device section
    with st.expander("➕ Add New Device"):
        col1, col2 = st.columns(2)
        with col1:
            device_name = st.text_input("Device Name")
            user_email = st.text_input("User Email")
        with col2:
            device_type = st.selectbox("Device Type", ["Laptop", "Desktop", "Mobile", "Tablet", "Server"])
            os_type = st.selectbox("Operating System", ["Windows 11", "macOS 13", "Ubuntu 22.04", "iOS 16", "Android 13"])
        
        if st.button("Add Device"):
            st.success(f"Device {device_name} added successfully!")
    
    st.divider()
    
    # Device list
    st.subheader("Managed Devices")
    
    devices_df = generate_device_data()
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("Filter by Status", ["All", "Secure", "At Risk", "Warning", "Updating"])
    with col2:
        risk_threshold = st.slider("Max Risk Score", 0, 100, 100)
    with col3:
        search_term = st.text_input("Search Devices")
    
    # Apply filters
    filtered_df = devices_df.copy()
    if status_filter != "All":
        filtered_df = filtered_df[filtered_df['Status'] == status_filter]
    filtered_df = filtered_df[filtered_df['Risk Score'] <= risk_threshold]
    if search_term:
        filtered_df = filtered_df[filtered_df['Device'].str.contains(search_term, case=False)]
    
    # Display devices
    for _, device in filtered_df.iterrows():
        st.markdown('<div class="device-container">', unsafe_allow_html=True)
        col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1, 1])
        
        with col1:
            st.write(f"**{device['Device']}**")
            st.write(device['User'])
        
        with col2:
            st.write(device['OS'])
            st.write(f"Last seen: {device['Last Seen'].strftime('%Y-%m-%d %H:%M')}")
        
        with col3:
            status_class = {
                'Secure': 'device-secure',
                'At Risk': 'device-risk',
                'Warning': 'device-warning',
                'Updating': 'device-info'
            }.get(device['Status'], '')
            
            st.markdown(f'<span class="{status_class}">{device["Status"]}</span>', unsafe_allow_html=True)
        
        with col4:
            st.write(f"Risk: {device['Risk Score']}%")
        
        with col5:
            st.button("Manage", key=f"manage_{device['Device']}")
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_reports():
    st.title("Security Reports")
    
    tab1, tab2, tab3 = st.tabs(["Compliance Report", "Threat Analysis", "Custom Reports"])
    
    with tab1:
        st.subheader("Compliance Dashboard")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Overall Compliance", "94%", "+2%")
            st.metric("GDPR Compliance", "96%", "+1%")
            st.metric("ISO 27001", "92%", "+3%")
        
        with col2:
            st.metric("Cyber Essentials", "98%", "0%")
            st.metric("Data Protection", "95%", "+1%")
            st.metric("Access Control", "91%", "+2%")
    
    with tab2:
        st.subheader("Threat Analysis Report")
        
        # Generate summary data
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threats Detected", "156", "+12")
        with col2:
            st.metric("Threats Blocked", "153", "+12")
        with col3:
            st.metric("Success Rate", "98.1%", "+0.3%")
        
        st.plotly_chart(create_threat_trends(), use_container_width=True)
    
    with tab3:
        st.subheader("Generate Custom Report")
        
        col1, col2 = st.columns(2)
        with col1:
            report_type = st.selectbox("Report Type", ["Security Summary", "Device Audit", "Compliance Check", "Incident Report"])
            date_range = st.date_input("Date Range", value=[datetime.now().date() - timedelta(days=30), datetime.now().date()])
        
        with col2:
            include_charts = st.checkbox("Include Charts", True)
            include_device_list = st.checkbox("Include Device List", True)
            report_format = st.selectbox("Format", ["PDF", "Excel", "CSV"])
        
        if st.button("Generate Report"):
            with st.spinner("Generating report..."):
                time.sleep(2)  # Simulate report generation
                st.success(f"{report_type} report generated successfully!")
                st.download_button(
                    label="📥 Download Report",
                    data="Sample report data...",
                    file_name=f"safebloq_{report_type.lower().replace(' ', '_')}.{report_format.lower()}",
                    mime="application/octet-stream"
                )

def show_team():
    st.title("Team Management")
    
    # Invite team member
    with st.expander("➕ Invite Team Member"):
        col1, col2 = st.columns(2)
        with col1:
            invite_email = st.text_input("Email Address")
            role = st.selectbox("Role", ["Admin", "Security Analyst", "Viewer", "Device Manager"])
        with col2:
            department = st.text_input("Department")
            permissions = st.multiselect("Permissions", ["View Devices", "Manage Devices", "View Reports", "Generate Reports", "Manage Team", "System Settings"])
        
        if st.button("Send Invitation"):
            st.success(f"Invitation sent to {invite_email}")
    
    st.divider()
    
    # Current team members
    st.subheader("Current Team Members")
    
    team_members = [
        {"Name": "John Smith", "Email": "john@company.com", "Role": "Admin", "Status": "Active", "Last Login": "2 hours ago"},
        {"Name": "Sarah Johnson", "Email": "sarah@company.com", "Role": "Security Analyst", "Status": "Active", "Last Login": "1 day ago"},
        {"Name": "Mike Davis", "Email": "mike@company.com", "Role": "Viewer", "Status": "Inactive", "Last Login": "1 week ago"},
        {"Name": "Lisa Chen", "Email": "lisa@company.com", "Role": "Device Manager", "Status": "Active", "Last Login": "3 hours ago"},
    ]
    
    for member in team_members:
        st.markdown('<div class="device-container">', unsafe_allow_html=True)
        col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1, 1])
        
        with col1:
            st.write(f"**{member['Name']}**")
            st.write(member['Email'])
        
        with col2:
            st.write(f"Role: {member['Role']}")
            st.write(f"Last login: {member['Last Login']}")
        
        with col3:
            status_color = "🟢" if member['Status'] == 'Active' else "🔴"
            st.write(f"{status_color} {member['Status']}")
        
        with col4:
            st.button("Edit", key=f"edit_{member['Email']}")
        
        with col5:
            st.button("Remove", key=f"remove_{member['Email']}")
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_support():
    st.title("Support & Documentation")
    
    tab1, tab2, tab3 = st.tabs(["User Documentation", "Security Documentation", "Support Tickets"])
    
    with tab1:
        st.subheader("User Guide")
        
        st.markdown("""
        ### Getting Started with Safebloq
        
        **Quick Setup Guide:**
        1. 🔐 Set up your account and team members
        2. 📱 Add your devices to the platform
        3. ⚙️ Configure security policies
        4. 📊 Monitor your security dashboard
        5. 📄 Generate compliance reports
        
        **Key Features:**
        - **Zero Trust Architecture**: Every device and user is verified
        - **Real-time Monitoring**: 24/7 threat detection and response
        - **Compliance Dashboard**: Track GDPR, ISO 27001, and Cyber Essentials
        - **Team Management**: Role-based access control
        - **Automated Reports**: Schedule and generate security reports
        
        **Dashboard Navigation:**
        - Use the sidebar to navigate between different sections
        - Toggle between dark and light themes
        - Refresh data using the refresh button
        """)
    
    with tab2:
        st.subheader("Security Documentation")
        
        st.markdown("""
        ### Security Architecture
        
        **Zero Trust Principles:**
        - Never trust, always verify
        - Assume breach mentality
        - Verify explicitly with multiple data points
        - Use least privilege access
        
        **Threat Detection:**
        - Real-time malware scanning
        - Behavioral analysis
        - Network traffic monitoring
        - Endpoint detection and response (EDR)
        
        **Compliance Features:**
        - GDPR data protection compliance
        - ISO 27001 security management
        - UK Cyber Essentials certification
        - Automated compliance reporting
        
        **Incident Response:**
        1. **Detection**: Automated threat identification
        2. **Analysis**: Security team investigation
        3. **Containment**: Isolate affected systems
        4. **Eradication**: Remove threats and vulnerabilities
        5. **Recovery**: Restore normal operations
        6. **Lessons Learned**: Improve security posture
        """)
    
    with tab3:
        st.subheader("Support Tickets")
        
        # Create new ticket
        with st.expander("🎫 Create Support Ticket"):
            col1, col2 = st.columns(2)
            with col1:
                ticket_subject = st.text_input("Subject")
                priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
            with col2:
                category = st.selectbox("Category", ["Technical Issue", "Feature Request", "Account Management", "Security Incident"])
                
            description = st.text_area("Description", height=100)
            
            if st.button("Submit Ticket"):
                st.success("Support ticket created successfully! Ticket ID: #ST-2024-001")
        
        st.divider()
        
        # Contact information
        st.subheader("Contact Support")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            **📧 Email Support:**
            support@safebloq.com
            
            **📞 Phone Support:**
            +44 20 1234 5678
            
            **🕒 Support Hours:**
            Monday - Friday: 9:00 AM - 6:00 PM GMT
            Emergency Support: 24/7
            """)
        
        with col2:
            st.markdown("""
            **💬 Live Chat:**
            Available during business hours
            
            **📚 Knowledge Base:**
            docs.safebloq.com
            
            **🌐 Community Forum:**
            community.safebloq.com
            """)

if __name__ == "__main__":
    main()
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import random
from datetime import datetime, timedelta
import time
import requests
import json
import base64
from io import BytesIO
import hashlib
import hmac
from typing import Dict, List, Optional, Any
import urllib.parse
import jwt
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import tempfile
import os

# Page config
st.set_page_config(
    page_title="Safebloq - Zero Trust Security",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_info' not in st.session_state:
    st.session_state.user_info = {}
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'
if 'security_score' not in st.session_state:
    st.session_state.security_score = random.randint(75, 95)

# Keycloak Integration
class KeycloakAuth:
    def __init__(self, server_url: str, realm: str, client_id: str, client_secret: str = None):
        self.server_url = server_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.realm_url = f"{self.server_url}/realms/{self.realm}"
        
    def get_auth_url(self, redirect_uri: str, state: str) -> str:
        """Generate Keycloak authorization URL"""
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'openid profile email',
            'state': state
        }
        auth_url = f"{self.realm_url}/protocol/openid-connect/auth"
        return f"{auth_url}?{urllib.parse.urlencode(params)}"
    
    def exchange_code_for_token(self, code: str, redirect_uri: str) -> Optional[Dict]:
        """Exchange authorization code for access token"""
        token_url = f"{self.realm_url}/protocol/openid-connect/token"
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': code,
            'redirect_uri': redirect_uri
        }
        
        if self.client_secret:
            data['client_secret'] = self.client_secret
        
        try:
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                return response.json()
            else:
                st.error(f"Token exchange failed: {response.text}")
                return None
        except Exception as e:
            st.error(f"Token exchange error: {str(e)}")
            return None
    
    def get_user_info(self, access_token: str) -> Optional[Dict]:
        """Get user information from Keycloak"""
        userinfo_url = f"{self.realm_url}/protocol/openid-connect/userinfo"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = requests.get(userinfo_url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                st.error(f"User info fetch failed: {response.text}")
                return None
        except Exception as e:
            st.error(f"User info error: {str(e)}")
            return None
    
    def verify_token(self, token: str) -> bool:
        """Verify JWT token"""
        try:
            # In production, you should verify with Keycloak's public key
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get('exp', 0)
            return datetime.utcnow().timestamp() < exp
        except:
            return False

# Wazuh Integration
class WazuhConnector:
    def __init__(self, manager_url: str, username: str, password: str):
        self.manager_url = manager_url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
        self.token_expires = None
        
    def authenticate(self) -> bool:
        """Authenticate with Wazuh API"""
        auth_url = f"{self.manager_url}/security/user/authenticate"
        
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=False  # In production, use proper SSL verification
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data['data']['token']
                # Wazuh tokens typically expire in 15 minutes
                self.token_expires = datetime.utcnow() + timedelta(minutes=15)
                return True
            else:
                st.error(f"Wazuh authentication failed: {response.text}")
                return False
        except Exception as e:
            st.error(f"Wazuh connection error: {str(e)}")
            return False
    
    def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid token"""
        if not self.token or (self.token_expires and datetime.utcnow() >= self.token_expires):
            return self.authenticate()
        return True
    
    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make authenticated request to Wazuh API"""
        if not self._ensure_authenticated():
            return None
        
        url = f"{self.manager_url}{endpoint}"
        headers = {'Authorization': f'Bearer {self.token}'}
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=False)
            if response.status_code == 200:
                return response.json()
            else:
                st.error(f"Wazuh API error: {response.text}")
                return None
        except Exception as e:
            st.error(f"Wazuh request error: {str(e)}")
            return None
    
    def get_agents(self) -> List[Dict]:
        """Get all Wazuh agents"""
        data = self._make_request('/agents')
        if data and 'data' in data:
            return data['data']['affected_items']
        return []
    
    def get_alerts(self, limit: int = 50, time_range: str = '24h') -> List[Dict]:
        """Get recent security alerts"""
        params = {
            'limit': limit,
            'sort': '-timestamp',
            'q': f'timestamp>now-{time_range}'
        }
        
        data = self._make_request('/security_events', params)
        if data and 'data' in data:
            return data['data']['affected_items']
        return []
    
    def get_ruleset_stats(self) -> Dict:
        """Get ruleset statistics"""
        data = self._make_request('/rules/stats')
        if data and 'data' in data:
            return data['data']
        return {}
    
    def get_security_summary(self) -> Dict:
        """Get security summary dashboard data"""
        agents = self.get_agents()
        alerts = self.get_alerts(limit=100)
        
        # Calculate summary stats
        total_agents = len(agents)
        active_agents = len([a for a in agents if a.get('status') == 'active'])
        
        # Alert severity breakdown
        alert_levels = {}
        for alert in alerts:
            level = alert.get('rule', {}).get('level', 0)
            severity = self._get_severity_name(level)
            alert_levels[severity] = alert_levels.get(severity, 0) + 1
        
        return {
            'total_agents': total_agents,
            'active_agents': active_agents,
            'inactive_agents': total_agents - active_agents,
            'total_alerts': len(alerts),
            'alert_levels': alert_levels,
            'recent_alerts': alerts[:10]
        }
    
    def _get_severity_name(self, level: int) -> str:
        """Convert alert level to severity name"""
        if level >= 12:
            return 'Critical'
        elif level >= 7:
            return 'High'
        elif level >= 4:
            return 'Medium'
        else:
            return 'Low'

# PDF Export Functionality
class PDFExporter:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        styles = {}
        
        # Title style
        styles['CustomTitle'] = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2E86AB')
        )
        
        # Subtitle style
        styles['CustomSubtitle'] = ParagraphStyle(
            'CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.HexColor('#4A4A4A')
        )
        
        # Alert styles
        styles['CriticalAlert'] = ParagraphStyle(
            'CriticalAlert',
            parent=self.styles['Normal'],
            backColor=colors.HexColor('#FF4757'),
            textColor=colors.white,
            borderPadding=5
        )
        
        return styles
    
    def create_security_report(self, data: Dict) -> BytesIO:
        """Create comprehensive security report PDF"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        
        # Title
        title = Paragraph("Safebloq Security Report", self.custom_styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Report metadata
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        meta_data = [
            ['Report Generated:', report_date],
            ['Report Type:', 'Comprehensive Security Analysis'],
            ['Security Score:', f"{data.get('security_score', 'N/A')}%"],
            ['Total Devices:', str(data.get('total_devices', 'N/A'))]
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 3*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.custom_styles['CustomSubtitle']))
        summary_text = f"""
        This report provides a comprehensive overview of the current security posture.
        Current security score: {data.get('security_score', 'N/A')}%.
        Total devices monitored: {data.get('total_devices', 'N/A')}.
        Active threats detected: {data.get('active_threats', 'N/A')}.
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Security Metrics
        if 'metrics' in data:
            story.append(Paragraph("Security Metrics", self.custom_styles['CustomSubtitle']))
            
            metrics_data = [['Metric', 'Value', 'Status']]
            for metric, value in data['metrics'].items():
                status = '✓ Good' if isinstance(value, (int, float)) and value > 80 else '⚠ Review'
                metrics_data.append([metric.replace('_', ' ').title(), str(value), status])
            
            metrics_table = Table(metrics_data, colWidths=[2*inch, 1*inch, 1*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(metrics_table)
            story.append(Spacer(1, 20))
        
        # Recent Alerts
        if 'alerts' in data:
            story.append(Paragraph("Recent Security Alerts", self.custom_styles['CustomSubtitle']))
            
            alert_data = [['Time', 'Alert Type', 'Severity', 'Device']]
            for alert in data['alerts'][:10]:  # Show top 10 alerts
                alert_data.append([
                    alert.get('time', 'Unknown'),
                    alert.get('type', 'Unknown'),
                    alert.get('severity', 'Unknown'),
                    alert.get('device', 'Unknown')
                ])
            
            alert_table = Table(alert_data, colWidths=[1.5*inch, 2*inch, 1*inch, 1.5*inch])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#FF6B6B')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(alert_table)
            story.append(Spacer(1, 20))
        
        # Device Status
        if 'devices' in data:
            story.append(Paragraph("Device Status Overview", self.custom_styles['CustomSubtitle']))
            
            device_data = [['Device', 'Status', 'Last Seen', 'Risk Score']]
            for device in data['devices'][:15]:  # Show top 15 devices
                device_data.append([
                    device.get('name', 'Unknown'),
                    device.get('status', 'Unknown'),
                    device.get('last_seen', 'Unknown'),
                    f"{device.get('risk_score', 0)}%"
                ])
            
            device_table = Table(device_data, colWidths=[2*inch, 1*inch, 1.5*inch, 1*inch])
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4ECDC4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(device_table)
        
        # Recommendations
        story.append(Spacer(1, 30))
        story.append(Paragraph("Security Recommendations", self.custom_styles['CustomSubtitle']))
        recommendations = [
            "• Review and update security policies regularly",
            "• Implement multi-factor authentication for all users",
            "• Ensure all devices have latest security patches",
            "• Monitor network traffic for suspicious activities",
            "• Conduct regular security awareness training"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

# Custom CSS for dark/light theme and modern styling
def load_css():
    theme = st.session_state.get('theme', 'dark')
    
    if theme == 'dark':
        bg_color = "#0e1117"
        text_color = "#fafafa"
        card_bg = "#262730"
        border_color = "#4a4a4a"
        sidebar_bg = "#1e1e1e"
        input_bg = "#2d2d2d"
        plotly_bg = "rgba(38, 39, 48, 0.8)"
    else:
        bg_color = "#ffffff"
        text_color = "#262626"
        card_bg = "#f8f9fa"
        border_color = "#e0e0e0"
        sidebar_bg = "#f0f2f6"
        input_bg = "#ffffff"
        plotly_bg = "rgba(248, 249, 250, 0.8)"
    
    st.markdown(f"""
    <style>
    /* Global theme styles */
    .stApp {{
        background-color: {bg_color};
        color: {text_color};
    }}
    
    /* Authentication form styling */
    .auth-container {{
        max-width: 400px;
        margin: 0 auto;
        padding: 2rem;
        background-color: {card_bg};
        border-radius: 15px;
        border: 1px solid {border_color};
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }}
    
    .auth-title {{
        text-align: center;
        font-size: 2rem;
        font-weight: bold;
        color: #2E86AB;
        margin-bottom: 2rem;
    }}
    
    /* Sidebar styling */
    .css-1d391kg {{
        background-color: {sidebar_bg};
    }}
    
    /* Main content area */
    .main > div {{
        padding-top: 2rem;
        background-color: {bg_color};
    }}
    
    /* Header styling */
    .safebloq-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 0;
        border-bottom: 2px solid {border_color};
        margin-bottom: 2rem;
        background-color: {card_bg};
        border-radius: 10px;
        padding: 1.5rem;
    }}
    
    .safebloq-logo {{
        font-size: 2rem;
        font-weight: bold;
        color: #2E86AB;
    }}
    
    /* Security score styling */
    .security-score-container {{
        text-align: center;
        padding: 2rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 15px;
        color: white;
        margin-bottom: 2rem;
    }}
    
    .security-score {{
        font-size: 3rem;
        font-weight: bold;
        margin: 1rem 0;
    }}
    
    /* Card styling */
    .metric-card {{
        background-color: {card_bg};
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid {border_color};
        margin-bottom: 1rem;
    }}
    
    /* Alert styling */
    .alert-critical {{
        background-color: #ff4757;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }}
    
    .alert-warning {{
        background-color: #ffa726;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }}
    
    .alert-info {{
        background-color: #42a5f5;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }}
    
    /* Device status styling */
    .device-secure {{
        color: #4caf50;
        font-weight: bold;
    }}
    
    .device-risk {{
        color: #ff5722;
        font-weight: bold;
    }}
    
    .device-warning {{
        color: #ff9800;
        font-weight: bold;
    }}
    
    /* Container styling */
    .device-container {{
        background-color: {card_bg};
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid {border_color};
        margin-bottom: 0.5rem;
    }}
    
    /* Wazuh integration styling */
    .wazuh-agent {{
        background-color: {card_bg};
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #2E86AB;
        margin-bottom: 0.5rem;
    }}
    
    .wazuh-alert {{
        background-color: {card_bg};
        padding: 0.8rem;
        border-radius: 5px;
        border-left: 4px solid #ff4757;
        margin-bottom: 0.3rem;
    }}
    
    /* Export button styling */
    .export-button {{
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        cursor: pointer;
        font-weight: bold;
    }}
    
    /* User info display */
    .user-info {{
        background-color: {card_bg};
        padding: 0.5rem 1rem;
        border-radius: 20px;
        border: 1px solid {border_color};
        margin-bottom: 1rem;
    }}
    
    /* Mobile responsive */
    @media (max-width: 768px) {{
        .safebloq-header {{
            flex-direction: column;
            text-align: center;
        }}
        
        .security-score {{
            font-size: 2rem;
        }}
        
        .auth-container {{
            margin: 1rem;
            padding: 1rem;
        }}
    }}
    </style>
    """, unsafe_allow_html=True)

# Authentication functions
def show_login():
    """Show Keycloak login interface"""
    load_css()
    
    st.markdown('<div class="auth-container">', unsafe_allow_html=True)
    st.markdown('<div class="auth-title">🔐 Safebloq Login</div>', unsafe_allow_html=True)
    
    # Keycloak configuration
    with st.expander("🔧 Keycloak Configuration", expanded=True):
        keycloak_url = st.text_input("Keycloak Server URL", value="http://localhost:8080")
        realm = st.text_input("Realm", value="safebloq")
        client_id = st.text_input("Client ID", value="safebloq-dashboard")
        client_secret = st.text_input("Client Secret (optional)", type="password")
        
        if st.button("🚀 Login with Keycloak", key="keycloak_login"):
            if keycloak_url and realm and client_id:
                # Initialize Keycloak auth
                keycloak = KeycloakAuth(keycloak_url, realm, client_id, client_secret)
                
                # Generate state for security
                state = hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()
                st.session_state.auth_state = state
                
                # Create redirect URI (in production, this would be your app's callback URL)
                redirect_uri = "http://localhost:8501"  # Adjust for your deployment
                
                # Get authorization URL
                auth_url = keycloak.get_auth_url(redirect_uri, state)
                
                st.markdown(f"""
                <div style="margin: 1rem 0; padding: 1rem; background-color: #e3f2fd; border-radius: 5px;">
                    <p><strong>To complete login:</strong></p>
                    <ol>
                        <li>Click the link below to login via Keycloak</li>
                        <li>After successful login, copy the authorization code from the URL</li>
                        <li>Paste it in the field below</li>
                    </ol>
                    <p><a href="{auth_url}" target="_blank">🔗 Login via Keycloak</a></p>
                </div>
                """, unsafe_allow_html=True)
                
                # Code input field
                auth_code = st.text_input("Authorization Code", help="Paste the code from the callback URL")
                
                if st.button("🔓 Complete Login") and auth_code:
                    # Exchange code for token
                    token_data = keycloak.exchange_code_for_token(auth_code, redirect_uri)
                    
                    if token_data:
                        # Get user info
                        user_info = keycloak.get_user_info(token_data['access_token'])
                        
                        if user_info:
                            st.session_state.authenticated = True
                            st.session_state.user_info = user_info
                            st.session_state.access_token = token_data['access_token']
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to get user information")
                    else:
                        st.error("❌ Login failed")
            else:
                st.error("Please fill in all required Keycloak configuration fields")
    
    # Demo login option
    st.divider()
    st.markdown("### 🧪 Demo Mode")
    st.info("For testing purposes, you can use demo mode without Keycloak")
    
    if st.button("🎯 Demo Login", key="demo_login"):
        st.session_state.authenticated = True
        st.session_state.user_info = {
            'preferred_username': 'demo_user',
            'email': 'demo@safebloq.com',
            'name': 'Demo User',
            'roles': ['security_analyst']
        }
        st.success("✅ Demo login successful!")
        st.rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_user_info():
    """Display current user information"""
    if st.session_state.authenticated:
        user_info = st.session_state.user_info
        
        st.markdown(f"""
        <div class="user-info">
            👤 <strong>{user_info.get('name', user_info.get('preferred_username', 'User'))}</strong>
            ({user_info.get('email', 'No email')})
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.session_state.user_info = {}
            if 'access_token' in st.session_state:
                del st.session_state.access_token
            st.rerun()

# Generate sample data functions (keeping existing ones)
@st.cache_data(ttl=300)
def generate_threat_data():
    dates = [datetime.now() - timedelta(days=x) for x in range(30, 0, -1)]
    threats = {
        'Date': dates,
        'Malware': [random.randint(0, 5) for _ in range(30)],
        'Phishing': [random.randint(0, 8) for _ in range(30)],
        'Intrusion': [random.randint(0, 3) for _ in range(30)],
        'DDoS': [random.randint(0, 2) for _ in range(30)]
    }
    return pd.DataFrame(threats)

@st.cache_data(ttl=300)
def generate_device_data():
    devices = []
    device_types = ['Laptop', 'Desktop', 'Mobile', 'Tablet', 'Server']
    statuses = ['Secure', 'At Risk', 'Warning', 'Updating']
    
    for i in range(20):
        devices.append({
            'Device': f"{random.choice(device_types)}-{i+1:03d}",
            'User': f"user{i+1}@company.com",
            'Status': random.choice(statuses),
            'Last Seen': datetime.now() - timedelta(hours=random.randint(0, 48)),
            'OS': random.choice(['Windows 11', 'macOS 13', 'Ubuntu 22.04', 'iOS 16', 'Android 13']),
            'Risk Score': random.randint(10, 90)
        })
    
    return pd.DataFrame(devices)

@st.cache_data(ttl=60)
def generate_live_alerts():
    alert_types = ['Malware Detected', 'Unsafe Device', 'Phishing Attempt', 'Outbound Denial', 'Login Anomaly']
    severities = ['Critical', 'Warning', 'Info']
    
    alerts = []
    for i in range(8):
        alerts.append({
            'Time': datetime.now() - timedelta(minutes=random.randint(0, 120)),
            'Alert': random.choice(alert_types),
            'Severity': random.choice(severities),
            'Device': f"Device-{random.randint(1, 50):03d}",
            'Status': random.choice(['Active', 'Investigating', 'Resolved'])
        })
    
    return sorted(alerts, key=lambda x: x['Time'], reverse=True)

# Security score gauge
def create_security_gauge(score):
    theme = st.session_state.get('theme', 'dark')
    
    if theme == 'dark':
        paper_bg = "rgba(38, 39, 48, 0.8)"
        plot_bg = "rgba(38, 39, 48, 0.8)"
        font_color = "#fafafa"
    else:
        paper_bg = "rgba(248, 249, 250, 0.8)"
        plot_bg = "rgba(248, 249, 250, 0.8)"
        font_color = "#262626"
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Security Score", 'font': {'color': font_color}},
        delta = {'reference': 85},
        gauge = {
            'axis': {'range': [None, 100], 'tickcolor': font_color, 'tickfont': {'color': font_color}},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 50], 'color': "lightgray"},
                {'range': [50, 80], 'color': "yellow"},
                {'range': [80, 100], 'color': "lightgreen"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor=paper_bg,
        plot_bgcolor=plot_bg,
        font=dict(color=font_color)
    )
    
    return fig

# Threat trends chart
def create_threat_trends():
    df = generate_threat_data()
    theme = st.session_state.get('theme', 'dark')
    
    if theme == 'dark':
        paper_bg = "rgba(38, 39, 48, 0.8)"
        plot_bg = "rgba(38, 39, 48, 0.8)"
        font_color = "#fafafa"
    else:
        paper_bg = "rgba(248, 249, 250, 0.8)"
        plot_bg = "rgba(248, 249, 250, 0.8)"
        font_color = "#262626"
    
    fig = go.Figure()
    
    colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
    threat_types = ['Malware', 'Phishing', 'Intrusion', 'DDoS']
    
    for i, threat_type in enumerate(threat_types):
        fig.add_trace(go.Scatter(
            x=df['Date'],
            y=df[threat_type],
            mode='lines+markers',
            name=threat_type,
            line=dict(color=colors[i], width=3),
            marker=dict(size=6)
        ))
    
    fig.update_layout(
        title="Threat Trends (Last 30 Days)",
        xaxis_title="Date",
        yaxis_title="Threats Detected",
        height=400,
        hovermode='x unified',
        paper_bgcolor=paper_bg,
        plot_bgcolor=plot_bg,
        font=dict(color=font_color),
        xaxis=dict(color=font_color),
        yaxis=dict(color=font_color)
    )
    
    return fig

# Wazuh Integration Pages
def show_wazuh_integration():
    """Show Wazuh SIEM integration page"""
    st.title("🛡️ Wazuh SIEM Integration")
    
    # Initialize Wazuh connector in session state
    if 'wazuh_connector' not in st.session_state:
        st.session_state.wazuh_connector = None
    
    # Configuration section
    st.subheader("Wazuh Configuration")
    
    with st.expander("🔧 Configure Wazuh Connection", expanded=not st.session_state.wazuh_connector):
        col1, col2 = st.columns(2)
        
        with col1:
            wazuh_url = st.text_input("Wazuh Manager URL", value="https://localhost:55000")
            username = st.text_input("Username", value="wazuh")
        
        with col2:
            password = st.text_input("Password", type="password")
        
        if st.button("🔗 Connect to Wazuh"):
            if wazuh_url and username and password:
                wazuh_connector = WazuhConnector(wazuh_url, username, password)
                if wazuh_connector.authenticate():
                    st.session_state.wazuh_connector = wazuh_connector
                    st.success("✅ Connected to Wazuh successfully!")
                    st.rerun()
                else:
                    st.error("❌ Failed to connect to Wazuh")
            else:
                st.error("Please fill in all connection details")
    
    # Show Wazuh data if connected
    if st.session_state.wazuh_connector:
        wazuh = st.session_state.wazuh_connector
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("🔄 Refresh Data"):
                st.cache_data.clear()
                st.rerun()
        
        with col2:
            st.success("🟢 Connected to Wazuh")
        
        st.divider()
        
        # Wazuh Dashboard
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🤖 Agents", "🚨 Alerts", "📈 Analytics"])
        
        with tab1:
            st.subheader("Security Overview")
            
            # Get summary data
            try:
                summary = wazuh.get_security_summary()
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Agents", summary.get('total_agents', 0))
                with col2:
                    st.metric("Active Agents", summary.get('active_agents', 0), 
                             delta=f"+{summary.get('active_agents', 0) - summary.get('inactive_agents', 0)}")
                with col3:
                    st.metric("Total Alerts", summary.get('total_alerts', 0))
                with col4:
                    critical_alerts = summary.get('alert_levels', {}).get('Critical', 0)
                    st.metric("Critical Alerts", critical_alerts, delta=f"+{critical_alerts}")
                
                # Alert level breakdown
                if summary.get('alert_levels'):
                    st.subheader("Alert Severity Distribution")
                    
                    labels = list(summary['alert_levels'].keys())
                    values = list(summary['alert_levels'].values())
                    colors_map = {'Critical': '#ff4757', 'High': '#ffa726', 'Medium': '#42a5f5', 'Low': '#4caf50'}
                    
                    fig = go.Figure(data=[go.Pie(
                        labels=labels, 
                        values=values,
                        marker=dict(colors=[colors_map.get(label, '#cccccc') for label in labels])
                    )])
                    
                    fig.update_layout(
                        height=400,
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)"
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
            except Exception as e:
                st.error(f"Failed to load Wazuh overview: {str(e)}")
        
        with tab2:
            st.subheader("Wazuh Agents")
            
            try:
                agents = wazuh.get_agents()
                
                if agents:
                    for agent in agents:
                        status_color = "🟢" if agent.get('status') == 'active' else "🔴"
                        
                        st.markdown(f"""
                        <div class="wazuh-agent">
                            <strong>{status_color} {agent.get('name', 'Unknown')} ({agent.get('id', 'N/A')})</strong><br>
                            IP: {agent.get('ip', 'Unknown')} | 
                            OS: {agent.get('os', {}).get('name', 'Unknown')} | 
                            Version: {agent.get('version', 'Unknown')}<br>
                            Last Keep Alive: {agent.get('lastKeepAlive', 'Unknown')}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("No agents found")
                    
            except Exception as e:
                st.error(f"Failed to load agents: {str(e)}")
        
        with tab3:
            st.subheader("Security Alerts")
            
            # Time range selector
            col1, col2 = st.columns([1, 3])
            with col1:
                time_range = st.selectbox("Time Range", ["1h", "6h", "24h", "7d"], index=2)
            
            try:
                alerts = wazuh.get_alerts(limit=50, time_range=time_range)
                
                if alerts:
                    for alert in alerts:
                        severity_level = alert.get('rule', {}).get('level', 0)
                        severity_name = wazuh._get_severity_name(severity_level)
                        severity_color = {
                            'Critical': '🔴', 'High': '🟠', 
                            'Medium': '🟡', 'Low': '🟢'
                        }.get(severity_name, '⚪')
                        
                        timestamp = alert.get('timestamp', 'Unknown')
                        rule_desc = alert.get('rule', {}).get('description', 'No description')
                        agent_name = alert.get('agent', {}).get('name', 'Unknown')
                        
                        st.markdown(f"""
                        <div class="wazuh-alert">
                            <strong>{severity_color} {severity_name} Alert (Level {severity_level})</strong><br>
                            <strong>Time:</strong> {timestamp}<br>
                            <strong>Agent:</strong> {agent_name}<br>
                            <strong>Description:</strong> {rule_desc}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"No alerts found in the last {time_range}")
                    
            except Exception as e:
                st.error(f"Failed to load alerts: {str(e)}")
        
        with tab4:
            st.subheader("Security Analytics")
            
            try:
                # Create alert trends chart
                alerts = wazuh.get_alerts(limit=100, time_range="24h")
                
                if alerts:
                    # Process alerts for visualization
                    alert_times = []
                    alert_levels = []
                    
                    for alert in alerts:
                        try:
                            # Parse timestamp
                            timestamp = alert.get('timestamp', '')
                            if timestamp:
                                alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                alert_times.append(alert_time)
                                alert_levels.append(wazuh._get_severity_name(
                                    alert.get('rule', {}).get('level', 0)
                                ))
                        except:
                            continue
                    
                    if alert_times:
                        # Create hourly alert count
                        df_alerts = pd.DataFrame({
                            'timestamp': alert_times,
                            'severity': alert_levels
                        })
                        
                        df_alerts['hour'] = df_alerts['timestamp'].dt.floor('H')
                        hourly_counts = df_alerts.groupby(['hour', 'severity']).size().unstack(fill_value=0)
                        
                        fig = go.Figure()
                        
                        severity_colors = {
                            'Critical': '#ff4757', 'High': '#ffa726', 
                            'Medium': '#42a5f5', 'Low': '#4caf50'
                        }
                        
                        for severity in hourly_counts.columns:
                            fig.add_trace(go.Scatter(
                                x=hourly_counts.index,
                                y=hourly_counts[severity],
                                mode='lines+markers',
                                name=severity,
                                line=dict(color=severity_colors.get(severity, '#cccccc'), width=2)
                            ))
                        
                        fig.update_layout(
                            title="Alert Trends (Last 24 Hours)",
                            xaxis_title="Time",
                            yaxis_title="Alert Count",
                            height=400,
                            hovermode='x unified'
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info("No alert data available for visualization")
                else:
                    st.info("No alerts found for analytics")
                    
            except Exception as e:
                st.error(f"Failed to load analytics: {str(e)}")

# PDF Export functionality
def show_export_options():
    """Show PDF export options"""
    st.subheader("📄 Export Security Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        report_type = st.selectbox("Report Type", [
            "Comprehensive Security Report",
            "Executive Summary",
            "Device Status Report",
            "Threat Analysis Report",
            "Compliance Report"
        ])
        
        include_charts = st.checkbox("Include Charts", True)
        include_alerts = st.checkbox("Include Recent Alerts", True)
        include_devices = st.checkbox("Include Device List", True)
    
    with col2:
        date_range = st.date_input(
            "Report Date Range",
            value=[datetime.now().date() - timedelta(days=7), datetime.now().date()]
        )
        
        report_format = st.selectbox("Format", ["PDF", "Excel", "CSV"])
    
    if st.button("📥 Generate Report"):
        with st.spinner("Generating report..."):
            try:
                # Collect data for report
                devices_df = generate_device_data()
                alerts = generate_live_alerts()
                
                report_data = {
                    'security_score': st.session_state.security_score,
                    'total_devices': len(devices_df),
                    'active_threats': len([a for a in alerts if a['Status'] == 'Active']),
                    'metrics': {
                        'compliance_score': 94,
                        'threats_blocked': 156,
                        'response_time': 2.3,
                        'uptime_percentage': 99.9
                    },
                    'alerts': [
                        {
                            'time': alert['Time'].strftime('%Y-%m-%d %H:%M'),
                            'type': alert['Alert'],
                            'severity': alert['Severity'],
                            'device': alert['Device']
                        } for alert in alerts
                    ],
                    'devices': [
                        {
                            'name': row['Device'],
                            'status': row['Status'],
                            'last_seen': row['Last Seen'].strftime('%Y-%m-%d %H:%M'),
                            'risk_score': row['Risk Score']
                        } for _, row in devices_df.iterrows()
                    ]
                }
                
                if report_format == "PDF":
                    pdf_exporter = PDFExporter()
                    pdf_buffer = pdf_exporter.create_security_report(report_data)
                    
                    st.download_button(
                        label="📄 Download PDF Report",
                        data=pdf_buffer.getvalue(),
                        file_name=f"safebloq_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf"
                    )
                
                elif report_format == "Excel":
                    # Create Excel report
                    with pd.ExcelWriter(BytesIO(), engine='openpyxl') as writer:
                        # Summary sheet
                        summary_df = pd.DataFrame([
                            ['Security Score', f"{report_data['security_score']}%"],
                            ['Total Devices', report_data['total_devices']],
                            ['Active Threats', report_data['active_threats']],
                            ['Compliance Score', f"{report_data['metrics']['compliance_score']}%"]
                        ], columns=['Metric', 'Value'])
                        summary_df.to_excel(writer, sheet_name='Summary', index=False)
                        
                        # Devices sheet
                        devices_df.to_excel(writer, sheet_name='Devices', index=False)
                        
                        # Alerts sheet
                        alerts_df = pd.DataFrame(report_data['alerts'])
                        alerts_df.to_excel(writer, sheet_name='Alerts', index=False)
                        
                        excel_buffer = writer.book.save(BytesIO())
                    
                    st.download_button(
                        label="📊 Download Excel Report",
                        data=excel_buffer,
                        file_name=f"safebloq_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                
                elif report_format == "CSV":
                    # Create CSV report
                    csv_buffer = StringIO()
                    
                    # Write summary
                    csv_buffer.write("SAFEBLOQ SECURITY REPORT\n")
                    csv_buffer.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    csv_buffer.write("SUMMARY\n")
                    csv_buffer.write(f"Security Score,{report_data['security_score']}%\n")
                    csv_buffer.write(f"Total Devices,{report_data['total_devices']}\n")
                    csv_buffer.write(f"Active Threats,{report_data['active_threats']}\n\n")
                    
                    # Write devices data
                    csv_buffer.write("DEVICES\n")
                    devices_df.to_csv(csv_buffer, index=False)
                    
                    st.download_button(
                        label="📋 Download CSV Report",
                        data=csv_buffer.getvalue(),
                        file_name=f"safebloq_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                
                st.success(f"✅ {report_format} report generated successfully!")
                
            except Exception as e:
                st.error(f"❌ Failed to generate report: {str(e)}")

# Main app
def main():
    if not st.session_state.authenticated:
        show_login()
        return
    
    load_css()
    
    # Header with user info
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("""
        <div class="safebloq-header">
            <div class="safebloq-logo">🔐 Safebloq</div>
            <div>Zero Trust Security Platform</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        show_user_info()
    
    # Sidebar navigation
    with st.sidebar:
        st.title("Navigation")
        page = st.selectbox(
            "Select Page",
            ["Dashboard", "Devices", "Wazuh SIEM", "Reports", "Team", "Support"]
        )
        
        st.divider()
        
        # Theme toggle
        current_theme = st.session_state.get('theme', 'dark')
        theme_emoji = "☀️" if current_theme == 'dark' else "🌙"
        theme_text = "Light Mode" if current_theme == 'dark' else "Dark Mode"
        
        if st.button(f"{theme_emoji} {theme_text}"):
            st.session_state.theme = 'light' if st.session_state.theme == 'dark' else 'dark'
            st.rerun()
        
        st.divider()
        
        # Quick stats
        st.subheader("Quick Stats")
        st.metric("Active Devices", "23", "+2")
        st.metric("Threats Blocked", "156", "+12")
        st.metric("Compliance Score", "94%", "+1%")
        
        # Export options
        st.divider()
        show_export_options()
    
    # Main content based on selected page
    if page == "Dashboard":
        show_dashboard()
    elif page == "Devices":
        show_devices()
    elif page == "Wazuh SIEM":
        show_wazuh_integration()
    elif page == "Reports":
        show_reports()
    elif page == "Team":
        show_team()
    elif page == "Support":
        show_support()

# Dashboard and other existing functions (keeping them the same)
def show_dashboard():
    st.title("Security Dashboard")
    
    # Top row - Security Score and key metrics
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    
    with col1:
        st.plotly_chart(create_security_gauge(st.session_state.security_score), use_container_width=True)
    
    with col2:
        st.metric("Active Threats", "3", "-2")
        st.metric("Devices Online", "23/25", "+1")
    
    with col3:
        st.metric("Blocked Attacks", "47", "+8")
        st.metric("Compliance", "94%", "+2%")
    
    with col4:
        st.metric("Response Time", "2.3s", "-0.5s")
        st.metric("Uptime", "99.9%", "0%")
    
    st.divider()
    
    # Second row - Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(create_threat_trends(), use_container_width=True)
    
    with col2:
        st.subheader("Live Security Alerts")
        alerts = generate_live_alerts()
        
        for alert in alerts[:6]:  # Show top 6 alerts
            severity_class = f"alert-{alert['Severity'].lower()}"
            time_str = alert['Time'].strftime("%H:%M")
            
            st.markdown(f"""
            <div class="{severity_class}">
                <strong>{time_str}</strong> - {alert['Alert']}<br>
                Device: {alert['Device']} | Status: {alert['Status']}
            </div>
            """, unsafe_allow_html=True)
    
    # Auto-refresh button
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

def show_devices():
    st.title("Device Management")
    
    # Add device section
    with st.expander("➕ Add New Device"):
        col1, col2 = st.columns(2)
        with col1:
            device_name = st.text_input("Device Name")
            user_email = st.text_input("User Email")
        with col2:
            device_type = st.selectbox("Device Type", ["Laptop", "Desktop", "Mobile", "Tablet", "Server"])
            os_type = st.selectbox("Operating System", ["Windows 11", "macOS 13", "Ubuntu 22.04", "iOS 16", "Android 13"])
        
        if st.button("Add Device"):
            st.success(f"Device {device_name} added successfully!")
    
    st.divider()
    
    # Device list
    st.subheader("Managed Devices")
    
    devices_df = generate_device_data()
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("Filter by Status", ["All", "Secure", "At Risk", "Warning", "Updating"])
    with col2:
        risk_threshold = st.slider("Max Risk Score", 0, 100, 100)
    with col3:
        search_term = st.text_input("Search Devices")
    
    # Apply filters
    filtered_df = devices_df.copy()
    if status_filter != "All":
        filtered_df = filtered_df[filtered_df['Status'] == status_filter]
    filtered_df = filtered_df[filtered_df['Risk Score'] <= risk_threshold]
    if search_term:
        filtered_df = filtered_df[filtered_df['Device'].str.contains(search_term, case=False)]
    
    # Display devices
    for _, device in filtered_df.iterrows():
        st.markdown('<div class="device-container">', unsafe_allow_html=True)
        col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1, 1])
        
        with col1:
            st.write(f"**{device['Device']}**")
            st.write(device['User'])
        
        with col2:
            st.write(device['OS'])
            st.write(f"Last seen: {device['Last Seen'].strftime('%Y-%m-%d %H:%M')}")
        
        with col3:
            status_class = {
                'Secure': 'device-secure',
                'At Risk': 'device-risk',
                'Warning': 'device-warning',
                'Updating': 'device-info'
            }.get(device['Status'], '')
            
            st.markdown(f'<span class="{status_class}">{device["Status"]}</span>', unsafe_allow_html=True)
        
        with col4:
            st.write(f"Risk: {device['Risk Score']}%")
        
        with col5:
            st.button("Manage", key=f"manage_{device['Device']}")
        
        st.markdown('</div>', unsafe_allow_html=True)

def show_reports():
    st.title("Security Reports")
    
    tab1, tab2, tab3 = st.tabs(["Compliance Report", "Threat Analysis", "Custom Reports"])
    
    with tab1:
        st.subheader("Compliance Dashboard")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Overall Compliance", "94%", "+2%")
            st.metric("GDPR Compliance", "96%", "+1%")
            st.metric("ISO 27001", "92%", "+3%")
        
        with col2:
            st.metric("Cyber Essentials", "98%", "0%")
            st.metric("Data Protection", "95%", "+1%")
            st.metric("Access Control", "91%", "+2%")
    
    with tab2:
        st.subheader("Threat Analysis Report")
        
        # Generate summary data
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threats Detected", "156", "+12")
        with col2:
            st.metric("Threats Blocked", "153", "+12")
        with col3:
            st.metric("Success Rate", "98.1%", "+0.3%")
        
        st.plotly_chart(create_threat_trends(), use_container_width=True)
    
    with tab3:
        st.subheader("Generate Custom Report")
        
        col1, col2 = st.columns(2)
        with col1:
            report_type = st.selectbox("Report Type", ["Security Summary", "Device Audit", "Compliance Check", "Incident Report"])
            date_range = st.date_input("Date Range", value=[datetime.now().date() - timedelta(days=30), datetime.now().date()])
        
        with col2:
            include_charts = st.checkbox("Include Charts", True)
            include_device_list = st.checkbox("Include Device List", True)
            report_format = st.selectbox("Format", ["PDF", "Excel", "CSV"])
        
        if st.button("Generate Report"):
            with st.spinner("Generating report..."):
                time.sleep(2)  # Simulate report generation
                st.success(f"{report_type} report generated successfully!")

def show_team():
    st.title("Team Management")
    
    # Invite team member
    with st.expander("➕ Invite Team Member"):
        col1, col2 = st.columns(2)
        with col1:
            invite_email = st.text_input("Email Address")
            role = st.selectbox("Role", ["Admin", "Security Analyst", "Viewer", "Device Manager"])
        with col2:
            department = st.text_input("Department")
            permissions = st.multiselect("Permissions", ["View Devices", "Manage Devices", "View Reports", "Generate Reports", "Manage Team", "System Settings"])
        
        if st.button("Send Invitation"):
            st.success(f"Invitation sent to {invite_email}")
    
    st.divider()
    
    # Current team members
    st.subheader("Current Team Members")
    
    team_members = [
        {"Name": "John Smith", "Email": "john@company.com", "Role": "Admin", "Status": "Active", "Last Login": "2 hours ago"},
        {"Name": "Sarah Johnson", "Email": "sarah@company.com", "Role": "Security Analyst", "Status": "Active", "Last Login": "1 day ago"},
        {"Name": "Mike Davis", "Email": "mike@company.com", "Role": "Viewer", "Status": "Inactive", "Last Login": "1 week"}
        ]

login_url = keycloak.get_auth_url(redirect_uri=REDIRECT_URI, state=session_state)
st.markdown(f"[🔐 Login with Safebloq]({login_url})", unsafe_allow_html=True)
query_params = st.experimental_get_query_params()
if "code" in query_params:
    code = query_params["code"][0]
    token = keycloak.exchange_code_for_token(code, REDIRECT_URI)
    if token:
        st.session_state["access_token"] = token["access_token"]
        st.session_state["user_info"] = keycloak.get_user_info(token["access_token"])
        st.success(f"Welcome, {st.session_state['user_info'].get('preferred_username')}")
if "access_token" in st.session_state and keycloak.verify_token(st.session_state["access_token"]):
    # Show Safebloq dashboard
    show_dashboard()
else:
    st.warning("Please log in to access your Safebloq dashboard.")


