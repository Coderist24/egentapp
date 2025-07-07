"""
Azure Multi-Agent AI Document Management and Chat System
A comprehensive platform for managing multiple AI agents with document handling and chat capabilities
"""

import streamlit as st
import time
import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path

# Azure imports
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.core.exceptions import AzureError
from azure.storage.blob import BlobServiceClient, BlobClient
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.models import VectorizedQuery

# Import Azure utilities
from azure_utils import AzureConfig, EnhancedAzureAIAgentClient, AzureAuthenticator

# Document processing imports (lazy loaded)
import io

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Azure Multi-Agent AI Platform",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern UI
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        background: linear-gradient(90deg, #0078d4, #106ebe);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    
    .agent-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
        border: 1px solid #e0e0e0;
        transition: all 0.3s ease;
        cursor: pointer;
    }
    
    .agent-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        border-color: #0078d4;
    }
    
    .agent-icon {
        font-size: 3rem;
        margin-bottom: 1rem;
        text-align: center;
    }
    
    .agent-title {
        font-size: 1.5rem;
        font-weight: bold;
        color: #0078d4;
        margin-bottom: 0.5rem;
        text-align: center;
    }
    
    .agent-description {
        color: #666;
        text-align: center;
        margin-bottom: 1rem;
    }
    
    .agent-stats {
        background: rgba(255,255,255,0.8);
        border-radius: 10px;
        padding: 0.5rem;
        font-size: 0.8rem;
        color: #555;
    }
    
    .chat-message {
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        animation: fadeIn 0.5s ease-in;
    }
    
    .user-message {
        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
        border-left: 4px solid #2196f3;
    }
    
    .assistant-message {
        background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%);
        border-left: 4px solid #9c27b0;
    }
    
    .error-message {
        background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
        border-left: 4px solid #f44336;
        color: #c62828;
    }
    
    .success-message {
        background: linear-gradient(135deg, #e8f5e8 0%, #c8e6c9 100%);
        border-left: 4px solid #4caf50;
        color: #2e7d32;
    }
    
    .login-container {
        max-width: 400px;
        margin: 2rem auto;
        padding: 2rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 20px;
        color: white;
    }
    
    .nav-tab {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        border: none;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 10px;
        margin: 0.2rem;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .nav-tab:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    .nav-tab.active {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        transform: scale(1.05);
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .permissions-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1rem;
        margin: 1rem 0;
    }
    
    .permission-card {
        background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
        border-radius: 10px;
        padding: 1rem;
        border: 1px solid #ddd;
    }
    
    .document-card {
        background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        border: 1px solid #ddd;
    }
</style>
""", unsafe_allow_html=True)

# Configuration class for Azure services
# Lazy loading for heavy libraries
@st.cache_resource
def load_heavy_libraries():
    """Load heavy libraries only when needed for performance optimization"""
    try:
        import PyPDF2
        import docx
        return {
            'PyPDF2': PyPDF2,
            'docx': docx
        }
    except ImportError as e:
        logger.warning(f"Heavy libraries not available: {e}")
        return {}

# Agent configuration and management
class AgentManager:
    """Manages agent configurations and operations"""
    
    def __init__(self, config: AzureConfig):
        self.config = config
        self.agents = self._load_default_agents()
    
    def _load_default_agents(self) -> Dict:
        """Load default agent configurations"""
        return {
            "hr_agent": {
                "id": "hr_agent",
                "name": "HR Assistant",
                "icon": "👥",
                "description": "Human Resources and Employee Management",
                "connection_string": "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                "agent_id": "asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                "container_name": "hr-documents",
                "search_index": "hr-search-index",
                "color": "#FF6B6B",
                "categories": ["recruitment", "policies", "training"]
            },
            "finance_agent": {
                "id": "finance_agent",
                "name": "Finance Assistant",
                "icon": "💰",
                "description": "Financial Analysis and Accounting Support",
                "connection_string": "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                "agent_id": "asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                "container_name": "finance-documents",
                "search_index": "finance-search-index",
                "color": "#4ECDC4",
                "categories": ["budgets", "reports", "invoices"]
            },
            "sales_agent": {
                "id": "sales_agent",
                "name": "Sales Assistant",
                "icon": "📈",
                "description": "Sales Support and Customer Relations",
                "connection_string": "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                "agent_id": "asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                "container_name": "sales-documents",
                "search_index": "sales-search-index",
                "color": "#45B7D1",
                "categories": ["proposals", "contracts", "presentations"]
            },
            "legal_agent": {
                "id": "legal_agent",
                "name": "Legal Assistant",
                "icon": "⚖️",
                "description": "Legal Document Analysis and Compliance",
                "connection_string": "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                "agent_id": "asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                "container_name": "legal-documents",
                "search_index": "legal-search-index",
                "color": "#8E44AD",
                "categories": ["contracts", "compliance", "regulations"]
            },
            "it_agent": {
                "id": "it_agent",
                "name": "IT Support",
                "icon": "💻",
                "description": "Technical Support and IT Operations",
                "connection_string": "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                "agent_id": "asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                "container_name": "it-documents",
                "search_index": "it-search-index",
                "color": "#F39C12",
                "categories": ["manuals", "procedures", "troubleshooting"]
            },
            "marketing_agent": {
                "id": "marketing_agent",
                "name": "Marketing Assistant",
                "icon": "📢",
                "description": "Marketing Campaigns and Brand Management",
                "connection_string": "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                "agent_id": "asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                "container_name": "marketing-documents",
                "search_index": "marketing-search-index",
                "color": "#E74C3C",
                "categories": ["campaigns", "content", "analytics"]
            }
        }
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent configuration by ID"""
        return self.agents.get(agent_id)
    
    def get_all_agents(self) -> Dict:
        """Get all agent configurations"""
        return self.agents
    
    def generate_azure_container_name(self, agent_id: str) -> str:
        """Generate Azure-compliant container name for agent"""
        # Azure container names must be lowercase, 3-63 chars, alphanumeric and hyphens
        base_name = f"agent-{agent_id.lower().replace('_', '-')}"
        return base_name[:63]  # Ensure max length compliance

# User authentication and authorization
class UserManager:
    """Manages user authentication and authorization"""
    
    def __init__(self):
        self.admin_credentials = {
            "username": "admin",
            "password": "G5x!bQz2Lp9"
        }
        self.users = self._load_default_users()
        self.azure_config = AzureConfig()
        self.azure_authenticator = AzureAuthenticator(self.azure_config)
    
    def _load_default_users(self) -> Dict:
        """Load default user configurations"""
        return {
            "admin": {
                "username": "admin",
                "role": "admin",
                "permissions": {
                    "all_agents": {
                        "access": True,
                        "chat": True,
                        "document_upload": True,
                        "document_delete": True,
                        "admin": True
                    }
                }
            },
            "user1": {
                "username": "user1",
                "role": "standard",
                "permissions": {
                    "hr_agent": {
                        "access": True,
                        "chat": True,
                        "document_upload": True,
                        "document_delete": False
                    },
                    "finance_agent": {
                        "access": True,
                        "chat": False,
                        "document_upload": False,
                        "document_delete": False
                    }
                }
            }
        }
    
    def authenticate_admin(self, username: str, password: str) -> bool:
        """Authenticate admin user"""
        return (username == self.admin_credentials["username"] and 
                password == self.admin_credentials["password"])
    
    def authenticate_azure_user(self, username: str, password: str) -> Dict:
        """Authenticate Azure user using Azure AD"""
        try:
            auth_result = self.azure_authenticator.authenticate_with_username_password(username, password)
            
            if auth_result["success"]:
                # Add user to local users dict if authenticated successfully
                user_data = auth_result["user"]
                self.users[username] = user_data
                logger.info(f"Azure user {username} authenticated and added to local users")
                
                return {
                    "success": True,
                    "user_data": user_data,
                    "message": auth_result["message"]
                }
            else:
                return {
                    "success": False,
                    "user_data": None,
                    "message": auth_result["message"]
                }
                
        except Exception as e:
            logger.error(f"Azure authentication error: {e}")
            return {
                "success": False,
                "user_data": None,
                "message": f"Authentication error: {str(e)}"
            }
    
    def get_user_permissions(self, username: str) -> Dict:
        """Get user permissions"""
        user = self.users.get(username, {})
        return user.get("permissions", {})
    
    def has_permission(self, username: str, agent_id: str, permission_type: str) -> bool:
        """Check if user has specific permission for agent"""
        permissions = self.get_user_permissions(username)
        
        # Admin has all permissions
        if username == "admin":
            return True
        
        # Check agent-specific permission
        agent_perms = permissions.get(agent_id, {})
        return agent_perms.get(permission_type, False)

# Document processing utilities
class DocumentProcessor:
    """Process and extract text from various document formats"""
    
    @staticmethod
    def extract_text_from_pdf(file_content: bytes) -> str:
        """Extract text from PDF file"""
        libs = load_heavy_libraries()
        if 'PyPDF2' not in libs:
            return "PDF processing not available. Please install PyPDF2."
        
        try:
            pdf_reader = libs['PyPDF2'].PdfReader(io.BytesIO(file_content))
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            logger.error(f"Error extracting text from PDF: {e}")
            return f"Error processing PDF: {str(e)}"
    
    @staticmethod
    def extract_text_from_docx(file_content: bytes) -> str:
        """Extract text from DOCX file"""
        libs = load_heavy_libraries()
        if 'docx' not in libs:
            return "DOCX processing not available. Please install python-docx."
        
        try:
            doc = libs['docx'].Document(io.BytesIO(file_content))
            text = ""
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
            return text
        except Exception as e:
            logger.error(f"Error extracting text from DOCX: {e}")
            return f"Error processing DOCX: {str(e)}"
    
    @staticmethod
    def extract_text_from_txt(file_content: bytes) -> str:
        """Extract text from TXT file"""
        try:
            return file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return file_content.decode('latin-1')
            except Exception as e:
                logger.error(f"Error extracting text from TXT: {e}")
                return f"Error processing TXT: {str(e)}"

# Initialize session state
def initialize_session_state():
    """Initialize all session state variables"""
    session_vars = {
        "authenticated": False,
        "current_user": None,
        "user_role": None,
        "current_page": "login",
        "selected_agent": None,
        "messages": {},  # Agent-specific message history
        "thread_ids": {},  # Agent-specific thread IDs
        "ai_clients": {},  # Agent-specific AI clients
        "connection_status": {},  # Agent-specific connection status
        "user_permissions": {},
        "agents": AgentManager(AzureConfig()).get_all_agents(),
        "user_manager": UserManager()
    }
    
    for key, default_value in session_vars.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

def main():
    """Main application entry point"""
    initialize_session_state()
    
    # Login is required - test mode removed
    
    # Import UI components
    from ui_components import (
        show_login_page, show_dashboard, show_agent_interface, 
        show_settings
    )
    
    # Route based on current page
    if st.session_state.current_page == "login":
        show_login_page()
    elif st.session_state.current_page == "dashboard":
        show_dashboard()
    elif st.session_state.current_page == "agent_interface":
        show_agent_interface()
    elif st.session_state.current_page == "settings":
        show_settings()

if __name__ == "__main__":
    main()
