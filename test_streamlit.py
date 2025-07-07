"""
Minimal test script to debug Azure Web App startup issues
This script tests if Streamlit can start with minimal configuration
"""

import streamlit as st
import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Minimal Streamlit app for testing"""
    
    # Log environment information
    logger.info("=== MINIMAL STREAMLIT TEST ===")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"PORT environment: {os.environ.get('PORT', 'Not set')}")
    logger.info(f"Streamlit version: {st.__version__}")
    
    # Simple page content
    st.title("🔥 Azure Web App Test")
    st.success("✅ Streamlit is working!")
    
    # Environment info
    st.subheader("Environment Information")
    st.write(f"**Port**: {os.environ.get('PORT', 'Not set')}")
    st.write(f"**Working Directory**: {os.getcwd()}")
    st.write(f"**Python Version**: {sys.version}")
    
    # Show current files
    st.subheader("Current Directory Files")
    try:
        files = os.listdir('.')
        for file in files:
            st.write(f"📄 {file}")
    except Exception as e:
        st.error(f"Error listing files: {e}")
    
    # Azure environment variables
    st.subheader("Azure Environment Variables")
    azure_vars = [
        'PORT', 'WEBSITE_SITE_NAME', 'AZURE_CLIENT_ID', 
        'AZURE_TENANT_ID', 'PYTHONPATH'
    ]
    
    for var in azure_vars:
        value = os.environ.get(var, 'Not set')
        if 'SECRET' in var or 'KEY' in var:
            value = '***configured***' if value != 'Not set' else 'Not set'
        st.write(f"**{var}**: {value}")

if __name__ == "__main__":
    main()
