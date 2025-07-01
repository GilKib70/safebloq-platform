import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import random
from datetime import datetime, timedelta
import time

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
