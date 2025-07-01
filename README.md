# safebloq-platform
# 🔐 Safebloq - Zero Trust Security Platform

A cloud-native, Zero Trust cybersecurity platform designed for UK SMBs and MSPs. Simplifies enterprise-grade security into a click-and-play dashboard.

[![Deploy to Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)

## 🌐 Quick Deploy from GitHub Web

**Perfect for GitHub Web IDE users! No local setup required.**

### 📋 Step-by-Step Deployment Guide

1. **Create Repository in GitHub Web:**
   - Go to [github.com](https://github.com) → New Repository
   - Name it `safebloq-platform`
   - Make it Public (required for Streamlit Cloud free tier)
   - Initialize with README ✅

2. **Open GitHub Web IDE:**
   - Press `.` (dot) in your new repository, OR
   - Change URL from `github.com` to `github.dev`
   - This opens VS Code in your browser

3. **Copy All Files:**
   - Create each file listed in the "Files to Create" section below
   - Copy-paste the exact content for each file
   - Use GitHub Web's file creator (click + icon)

4. **Deploy to Streamlit Cloud:**
   - Visit [share.streamlit.io](https://share.streamlit.io)
   - Sign in with your GitHub account
   - Click "New app" → "From existing repo"
   - Select your `safebloq-platform` repository
   - Main file path: `app.py`
   - Click "Deploy!" 🚀

### 📁 Files to Create in GitHub Web

**Essential files you need to create:**

```
📁 Your Repository Root
├── 📄 app.py                    # Main application (copy from artifact above)
├── 📄 requirements.txt          # Dependencies (copy from artifact above)  
├── 📄 README.md                 # This file
├── 📁 .streamlit/
│   └── 📄 config.toml          # Config (copy from artifact above)
└── 📁 .github/
    └── 📁 workflows/
        └── 📄 deploy.yml       # CI/CD (copy from artifact above)
```

## ✨ Platform Features

### 🛡️ Zero Trust Security
- **Device Authentication** - Every device verified before access
- **Real-time Monitoring** - 24/7 threat detection and response  
- **Behavioral Analysis** - AI-powered anomaly detection
- **Compliance Dashboard** - GDPR, ISO 27001, Cyber Essentials

### 📊 Interactive Dashboard
- **Security Score Gauge** - Live security posture visualization
- **Threat Trends** - 30-day attack pattern analysis
- **Live Alert Feed** - Real-time security notifications
- **Device Management** - Complete endpoint visibility

### 👥 Team & Access Control
- **Role-Based Access** - Admin, Analyst, Viewer permissions
- **Team Invitations** - Easy onboarding workflow
- **Audit Trails** - Complete access logging
- **Multi-tenant Support** - Perfect for MSPs

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| 🖥️ **Frontend** | Streamlit | Python-native web dashboard |
| 🎨 **Styling** | Custom CSS | Modern responsive design |
| 📊 **Charts** | Plotly | Interactive data visualizations |
| 📈 **Data** | Pandas | Data processing and analysis |
| ☁️ **Hosting** | Streamlit Cloud | Zero-config deployment |

## 🚀 GitHub Web Workflow

### Creating Files in GitHub Web IDE:

1. **Open your repo** → Press `.` for web IDE
2. **Create new file** → Click the `+` icon next to folders
3. **Folder structure:** Use `/` in filename (e.g., `.streamlit/config.toml`)
4. **Copy content** → Paste from the artifacts above
5. **Commit changes** → Use Source Control panel (Ctrl+Shift+G)

### Streamlit Cloud Auto-Deploy:

- **Automatic:** Any push to `main` branch triggers redeploy
- **Manual:** Click "Reboot app" in Streamlit Cloud dashboard
- **Logs:** Check deployment status in Streamlit Cloud

## 📱 Mobile-First Design

The platform is optimized for mobile devices and GitHub Web IDE development:

- **Responsive Layout** - Works on phones, tablets, desktops
- **Touch-Friendly** - Large buttons and intuitive navigation  
- **Fast Loading** - Optimized for mobile networks
- **Progressive Web App** - Can be installed on mobile devices

## 🔧 Configuration

### Environment Variables (Optional)
Set these in Streamlit Cloud → App Settings → Advanced:

```bash
# Optional configurations
STREAMLIT_THEME=dark
REFRESH_INTERVAL=300
MAX_DEVICES=100
```

## 📈 Roadmap

### 🔄 Next Features (Ready to Build)
- [ ] **Wazuh Integration** - Real endpoint monitoring
- [ ] **PDF Report Export** - Automated compliance reports
- [ ] **Email Notifications** - Daily security summaries
- [ ] **Keycloak SSO** - Enterprise authentication
- [ ] **Mobile PWA** - Installable mobile app

### 🎯 Target Integrations
- **Threat Intel:** AbuseIPDB, AlienVault OTX
- **Endpoints:** Wazuh, OSSEC
- **Identity:** Keycloak, Active Directory
- **Communications:** Slack, Teams, Email

## 🆘 Support

### 📞 Having Issues?

1. **Streamlit Cloud Issues:** Check [docs.streamlit.io](https://docs.streamlit.io)
2. **GitHub Web Issues:** Try refreshing or use incognito mode
3. **App Issues:** Check browser console (F12) for errors

### 💬 Get Help
- **Create Issue:** Use GitHub Issues tab
- **Documentation:** Check Streamlit docs
- **Community:** Streamlit Community Forum

---

**🚀 Ready to deploy? Start by creating your repository and copying the files!**
