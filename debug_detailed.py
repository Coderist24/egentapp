"""
Debug version of the Streamlit app to identify startup issues
"""
import streamlit as st
import traceback
import sys
import os

def debug_main():
    """Debug version of main with detailed error reporting"""
    try:
        st.write("🔍 **Debug Mode Active**")
        st.write("Python version:", sys.version)
        st.write("Current working directory:", os.getcwd())
        st.write("Environment variables loaded:", len(os.environ))
        
        # Test imports step by step
        st.write("📦 **Testing Imports...**")
        
        try:
            import azure_utils
            st.success("✅ azure_utils imported successfully")
        except Exception as e:
            st.error(f"❌ Failed to import azure_utils: {e}")
            st.code(traceback.format_exc())
        
        try:
            import ui_components
            st.success("✅ ui_components imported successfully")
        except Exception as e:
            st.error(f"❌ Failed to import ui_components: {e}")
            st.code(traceback.format_exc())
        
        try:
            from ui_components import show_login_page, show_dashboard, show_agent_interface, show_settings
            st.success("✅ UI component functions imported successfully")
        except Exception as e:
            st.error(f"❌ Failed to import UI functions: {e}")
            st.code(traceback.format_exc())
        
        # Test session state initialization
        st.write("🔧 **Testing Session State...**")
        try:
            # Initialize session state variables
            session_vars = {
                "authenticated": False,
                "user_info": None,
                "current_page": "login",
                "selected_agent": None,
                "chat_history": [],
                "uploaded_documents": [],
                "search_results": [],
                "agent_configs": {},
                "azure_client": None,
                "user_manager": None
            }
            
            for key, default_value in session_vars.items():
                if key not in st.session_state:
                    st.session_state[key] = default_value
            
            st.success("✅ Session state initialized successfully")
            st.write("Session state keys:", list(st.session_state.keys()))
        except Exception as e:
            st.error(f"❌ Failed to initialize session state: {e}")
            st.code(traceback.format_exc())
        
        # Test calling the login page
        st.write("🔐 **Testing Login Page...**")
        try:
            from ui_components import show_login_page
            st.write("About to call show_login_page()...")
            show_login_page()
            st.success("✅ Login page displayed successfully")
        except Exception as e:
            st.error(f"❌ Failed to display login page: {e}")
            st.code(traceback.format_exc())
        
    except Exception as e:
        st.error(f"🚨 **Critical Error in Debug Main**: {e}")
        st.code(traceback.format_exc())

if __name__ == "__main__":
    st.set_page_config(
        page_title="Debug - Azure Multi-Agent AI Platform",
        page_icon="🐛",
        layout="wide"
    )
    
    st.title("🐛 Debug Mode - Azure Multi-Agent AI Platform")
    debug_main()
