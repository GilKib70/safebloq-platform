#!/usr/bin/env python3
"""
Safebloq Platform Setup Validator
Run this in GitHub Web IDE to validate your setup before deploying to Streamlit Cloud.
"""

import os
import sys
from pathlib import Path

def check_mark(condition, message):
    """Print check mark or X based on condition"""
    if condition:
        print(f"✅ {message}")
        return True
    else:
        print(f"❌ {message}")
        return False

def warning_mark(condition, message):
    """Print warning for optional items"""
    if condition:
        print(f"✅ {message}")
    else:
        print(f"⚠️  {message}")

def main():
    print("🔐 Safebloq Platform Setup Validator")
    print("=" * 50)
    
    all_good = True
    
    # Check required files
    print("\n📋 Required Files Check:")
    required_files = [
        ("app.py", "Main Streamlit application"),
        ("requirements.txt", "Python dependencies"),
        ("README.md", "Project documentation"),
    ]
    
    for file_path, description in required_files:
        exists = Path(file_path).exists()
        all_good &= check_mark(exists, f"{description} ({file_path})")
    
    # Check optional files
    print("\n📁 Optional Files Check:")
    optional_files = [
        (".streamlit/config.toml", "Streamlit configuration"),
        (".github/workflows/deploy.yml", "GitHub Actions CI/CD"),
    ]
    
    for file_path, description in optional_files:
        exists = Path(file_path).exists()
        warning_mark(exists, f"{description} ({file_path})")
    
    # Check file contents
    print("\n📄 File Content Validation:")
    
    # Validate app.py
    if Path("app.py").exists():
        try:
            with open("app.py", "r") as f:
                content = f.read()
                has_streamlit = "import streamlit" in content
                has_main = "def main():" in content
                has_page_config = "st.set_page_config" in content
                
                all_good &= check_mark(has_streamlit, "app.py imports Streamlit")
                all_good &= check_mark(has_main, "app.py has main() function")
                all_good &= check_mark(has_page_config, "app.py sets page configuration")
        except Exception as e:
            all_good &= check_mark(False, f"app.py is readable: {e}")
    
    # Validate requirements.txt
    if Path("requirements.txt").exists():
        try:
            with open("requirements.txt", "r") as f:
                content = f.read()
                has_streamlit = "streamlit" in content
                has_plotly = "plotly" in content
                has_pandas = "pandas" in content
                
                all_good &= check_mark(has_streamlit, "requirements.txt includes streamlit")
                all_good &= check_mark(has_plotly, "requirements.txt includes plotly")
                all_good &= check_mark(has_pandas, "requirements.txt includes pandas")
        except Exception as e:
            all_good &= check_mark(False, f"requirements.txt is readable: {e}")
    
    # Python version check
    print("\n🐍 Python Environment:")
    python_version = sys.version_info
    python_ok = python_version >= (3, 8)
    check_mark(python_ok, f"Python version {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # Final assessment
    print("\n" + "=" * 50)
    if all_good:
        print("🎉 SUCCESS! Your Safebloq platform is ready for deployment!")
        print("\n📋 Next Steps:")
        print("1. Commit all files to your GitHub repository")
        print("2. Visit https://share.streamlit.io")
        print("3. Sign in with GitHub")
        print("4. Click 'New app' → 'From existing repo'")
        print("5. Select your repository")
        print("6. Set main file path: app.py")
        print("7. Click 'Deploy!' 🚀")
        print("\n🌐 Your app will be available at:")
        print("https://your-repo-name.streamlit.app")
    else:
        print("⚠️  Some issues found. Please fix the ❌ items above before deploying.")
        print("\n🔧 Common fixes:")
        print("- Make sure all required files are created")
        print("- Check file contents match the provided templates")
        print("- Ensure files are in the correct directories")
    
    print("\n💡 Need help? Check the README.md for detailed instructions!")

if __name__ == "__main__":
    main()
