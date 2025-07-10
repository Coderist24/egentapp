"""
Azure Multi-Agent AI Document Management and Chat System
A comprehensive platform for managing multiple AI agents with document handling and chat capabilities
"""

import streamlit as st
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    logging.info("Loaded environment variables")
except ImportError:
    logging.info("python-dotenv not available, using system environment variables")

# Azure imports
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.core.exceptions import AzureError
from azure.storage.blob import BlobServiceClient, BlobClient
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.models import VectorizedQuery

# Import Azure utilities
from azure_utils import AzureConfig, EnhancedAzureAIAgentClient, AzureAuthenticator, BlobStorageUserManager, BlobStorageAgentManager

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
    
    .icon-selector-button {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border: 2px solid #dee2e6;
        border-radius: 10px;
        padding: 0.8rem;
        margin: 0.2rem;
        font-size: 1.5rem;
        cursor: pointer;
        transition: all 0.3s ease;
        text-align: center;
        min-height: 60px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    
    .icon-selector-button:hover {
        background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
        border-color: #0078d4;
        transform: scale(1.05);
        box-shadow: 0 4px 12px rgba(0, 120, 212, 0.3);
        color: white;
    }
    
    .icon-selected {
        background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        border-color: #28a745;
        color: white;
        transform: scale(1.05);
        box-shadow: 0 4px 12px rgba(40, 167, 69, 0.3);
    }
    
    .icon-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
        gap: 0.5rem;
        margin: 1rem 0;
        padding: 1rem;
        background: #f8f9fa;
        border-radius: 10px;
        border: 1px solid #dee2e6;
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
    """Manages agent configurations and operations - now using blob storage"""
    
    def __init__(self, config: AzureConfig):
        # Initialize without any extra parameters
        self.blob_agent_manager = BlobStorageAgentManager(config)
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent configuration by ID"""
        try:
            return self.blob_agent_manager.get_agent(agent_id)
        except TypeError as e:
            # Handle the error gracefully
            logger.error(f"Error getting agent: {e}")
            return None
    
    def get_all_agents(self) -> Dict[str, Dict]:
        """Get all agent configurations"""
        return self.blob_agent_manager.get_all_agents()
    
    def get_active_agents(self) -> Dict[str, Dict]:
        """Get only active agent configurations"""
        return self.blob_agent_manager.get_active_agents()
    
    def add_agent(self, agent_config: Dict) -> bool:
        """Add a new agent configuration"""
        return self.blob_agent_manager.add_agent(agent_config)
    
    def update_agent(self, agent_id: str, agent_config: Dict) -> bool:
        """Update an existing agent configuration"""
        return self.blob_agent_manager.update_agent(agent_id, agent_config)
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent configuration"""
        return self.blob_agent_manager.delete_agent(agent_id)
    
    def set_agent_status(self, agent_id: str, status: str) -> bool:
        """Set agent status (active/inactive)"""
        return self.blob_agent_manager.set_agent_status(agent_id, status)
    
    def generate_azure_container_name(self, agent_id: str) -> str:
        """Generate Azure-compliant container name for agent"""
        return self.blob_agent_manager.generate_azure_container_name(agent_id)

# User authentication and authorization
class UserManager:
    """Manages user authentication and authorization - now using blob storage"""
    
    def __init__(self):
        self.blob_user_manager = BlobStorageUserManager(AzureConfig())
    
    def authenticate_admin(self, username: str, password: str) -> bool:
        """Authenticate admin user"""
        return self.blob_user_manager.authenticate_admin(username, password)
    
    def authenticate_azure_user(self, username: str, password: str) -> Dict:
        """Authenticate Azure user using Azure AD"""
        return self.blob_user_manager.authenticate_azure_user(username, password)
    
    def get_user_permissions(self, username: str) -> Dict:
        """Get user permissions"""
        return self.blob_user_manager.get_user_permissions(username)
    
    def has_permission(self, username: str, agent_id: str, permission_type: str) -> bool:
        """Check if user has specific permission for agent"""
        return self.blob_user_manager.has_permission(username, agent_id, permission_type)
    
    def add_user(self, username: str, role: str = "standard", permissions: List[str] = None) -> bool:
        """Add a new user"""
        return self.blob_user_manager.add_user(username, role, permissions or [])
    
    def update_user_permissions(self, username: str, permissions: List[str]) -> bool:
        """Update user permissions"""
        return self.blob_user_manager.update_user_permissions(username, permissions)
    
    def delete_user(self, username: str) -> bool:
        """Delete a user"""
        return self.blob_user_manager.delete_user(username)
    
    def get_all_users(self) -> Dict[str, Dict]:
        """Get all users"""
        return self.blob_user_manager.get_all_users()

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
    # Initialize Azure config and agent manager
    azure_config = AzureConfig()
    
    try:
        agent_manager = AgentManager(azure_config)
        agents = agent_manager.get_all_agents()
        
        # If no agents loaded from blob storage, load from backup configuration
        if not agents:
            logger.info("No agents in blob storage, loading from backup configuration...")
            backup_path = "config_backup/agent_configs.json"
            if os.path.exists(backup_path):
                with open(backup_path, 'r', encoding='utf-8') as f:
                    all_agents = json.load(f)
                # Filter enabled agents and ensure all required fields
                agents = {}
                for agent_id, config in all_agents.items():
                    if config.get('enabled', True):
                        # Ensure all required fields with defaults
                        agents[agent_id] = {
                            'id': agent_id,
                            'name': config.get('name', agent_id),
                            'icon': config.get('icon', '🤖'),
                            'description': config.get('description', 'No description available'),
                            'color': config.get('gradient', '#1e40af 0%, #1e3a8a 100%'),
                            'container_name': config.get('container', f'{agent_id}-documents'),
                            'categories': config.get('categories', ['general']),
                            'connection_string': config.get('connection_string', ''),
                            'agent_id': config.get('agent_id', ''),
                            'search_index': config.get('search_index', f'{agent_id}-index'),
                            'enabled': config.get('enabled', True)
                        }
                logger.info(f"Loaded {len(agents)} agents from backup configuration")
            else:
                logger.warning("Backup configuration not found, creating sample agents...")
                agents = {
                    "sample": {
                        "id": "sample",
                        "name": "Sample Agent",
                        "icon": "🤖",
                        "container_name": "sample-docs",
                        "color": "#1e40af 0%, #1e3a8a 100%",
                        "description": "Sample agent for testing",
                        "categories": ["general"],
                        "connection_string": "",
                        "agent_id": "",
                        "search_index": "sample-index",
                        "enabled": True
                    },
                    "scm": {
                        "id": "scm",
                        "name": "SCM",
                        "container_name": "scm-documents",
                        "icon": "📦",
                        "color": "#0078d4 0%, #106ebe 100%",
                        "description": "scm döküman yönetimi",
                        "categories": ["supply_chain"],
                        "connection_string": "",
                        "agent_id": "",
                        "search_index": "scm-index",
                        "enabled": True
                    },
                    "legal": {
                        "id": "legal",
                        "name": "Hukuk",
                        "container_name": "legal-documents",
                        "icon": "⚖️",
                        "color": "#7c3aed 0%, #6d28d9 100%",
                        "description": "Hukuki danışmanlık, sözleşme yönetimi, uyumluluk kontrolleri",
                        "categories": ["legal"],
                        "connection_string": "",
                        "agent_id": "",
                        "search_index": "legal-index",
                        "enabled": True
                    },
                    "it": {
                        "id": "it",
                        "name": "IT",
                        "icon": "🌐",
                        "container_name": "it-documents",
                        "color": "#1e40af 0%, #1e3a8a 100%",
                        "description": "IT destek ve sistem yönetimi",
                        "categories": ["technology"],
                        "connection_string": "",
                        "agent_id": "",
                        "search_index": "it-index",
                        "enabled": True
                    }
                }
        
        # Safety check: ensure agents is always a dictionary
        if not isinstance(agents, dict):
            logger.warning(f"Agent manager returned non-dict type: {type(agents)}")
            agents = {}
    except Exception as e:
        logger.error(f"Error initializing agent manager: {e}")
        # Fallback to backup configuration even on error
        backup_path = "config_backup/agent_configs.json"
        if os.path.exists(backup_path):
            try:
                with open(backup_path, 'r', encoding='utf-8') as f:
                    all_agents = json.load(f)
                # Filter enabled agents and ensure all required fields
                agents = {}
                for agent_id, config in all_agents.items():
                    if config.get('enabled', True):
                        # Ensure all required fields with defaults
                        agents[agent_id] = {
                            'id': agent_id,
                            'name': config.get('name', agent_id),
                            'icon': config.get('icon', '🤖'),
                            'description': config.get('description', 'No description available'),
                            'color': config.get('gradient', '#1e40af 0%, #1e3a8a 100%'),
                            'container_name': config.get('container', f'{agent_id}-documents'),
                            'categories': config.get('categories', ['general']),
                            'connection_string': config.get('connection_string', ''),
                            'agent_id': config.get('agent_id', ''),
                            'search_index': config.get('search_index', f'{agent_id}-index'),
                            'enabled': config.get('enabled', True)
                        }
                logger.info(f"Fallback: Loaded {len(agents)} agents from backup configuration")
            except Exception as backup_error:
                logger.error(f"Error loading backup configuration: {backup_error}")
                agents = {}
        else:
            agents = {}
    
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
        "agents": agents,
        "user_manager": UserManager()
    }
    
    for key, default_value in session_vars.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

def main():
    """Main application entry point"""
    initialize_session_state()
    
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
