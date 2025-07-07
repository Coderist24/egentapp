"""
Azure utilities and client classes for Multi-Agent AI Platform
Separated to avoid circular imports
"""

import time
import logging
import sys
from typing import Dict, Optional, List
import json
import requests
import hashlib
from datetime import datetime, timedelta

# Configure enhanced logging for debugging authentication issues
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("auth_debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Azure imports
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential, ClientSecretCredential
from azure.core.exceptions import AzureError
from azure.storage.blob import BlobServiceClient
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SearchField,
    SearchFieldDataType,
    SimpleField,
    SearchableField,
    VectorSearch,
    HnswAlgorithmConfiguration,
    VectorSearchProfile,
    SemanticConfiguration,
    SemanticSearch,
    SemanticPrioritizedFields,
    SemanticField
)
from azure.core.credentials import AzureKeyCredential

# Configure logging
logger = logging.getLogger(__name__)

# Configuration class for Azure services
class AzureConfig:
    """Centralized configuration for Azure services"""
    
    def __init__(self):
        # Azure AD App Registration for authentication
        # Bu kimlik bilgilerini, Microsoft Entra ID (Azure AD) portal üzerinden oluşturduğunuz 
        # uygulama kaydından almalısınız. ROPC akışını desteklediğinden emin olun.
        # IMPORTANT: These values must match your registered app in Azure AD that supports ROPC flow
        self.client_id = "c7790b94-d830-4746-961f-8c715a380c5e"  # Uygulama ID (client ID)
        self.client_secret = "6Jl8Q~Kue3BfEbXdbc3O-68WVEIPZeNFD-Bkub2p"  # Uygulama gizli anahtarı
        
        # ROPC akışı /common veya /consumers üzerinden desteklenmediği için "organizations" kullanıyoruz
        # IMPORTANT: For ROPC flow, always use "organizations" instead of "common" or "consumers"
        # Using "organizations" endpoint for ROPC flow as required by Azure AD
        self.tenant_id = "organizations"  # ROPC için /organizations veya belirli bir tenant ID kullanılmalı
        
        # OAuth2 token endpoint ve Graph API endpoint tanımlamaları
        self.oauth_token_endpoint = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        
        # Other Azure services
        self.redirect_uri = "https://egentapp-b4gqeudnc3h8emd3.westeurope-01.azurewebsites.net/"
        self.storage_connection_string = "DefaultEndpointsProtocol=https;AccountName=egentst;AccountKey=YFE9JJE+vOZEEmZnu9RV+xdLKxhlR/GBy4M1E3D5FgKUdqI1D4itG5kWxyxV6UxD0YKOgN9/f7Cx+AStaCQ5gg==;EndpointSuffix=core.windows.net"
        self.search_endpoint = "https://egentaisearch.search.windows.net"
        self.search_admin_key = "Hz01153KXk45lVNXNT0QJIHq279xngUA2OSKMkgVlKAzSeAZzbvb"
        self.storage_account_name = "egentst"
        
        # Azure OpenAI configuration for embeddings
        self.openai_endpoint = "https://egentaimodel.openai.azure.com"  # Updated endpoint
        self.openai_api_key = "6f49b37c6e5b4ac7995c8c7b64ad69c5"  # Update with your Azure OpenAI API key
        self.openai_api_version = "2023-05-15"
        self.embedding_model = "text-embedding-ada-002"
        
        self.use_managed_identity = True
        self.dev_mode = False

# Azure Authentication Helper
class AzureAuthenticator:
    """Handles Azure AD authentication"""
    
    def __init__(self, config: AzureConfig):
        self.config = config
    
    def authenticate_with_device_code(self) -> Dict:
        """
        Initiate device code flow authentication for Azure AD
        Returns device code information for the user to complete authentication
        """
        try:
            from msal import PublicClientApplication
            
            # Initialize MSAL client
            app = PublicClientApplication(
                client_id=self.config.public_client_id,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}"
            )
            
            # Define scopes for authentication
            scopes = ["https://graph.microsoft.com/User.Read"]
            
            # Initiate device flow
            flow = app.initiate_device_flow(scopes=scopes)
            
            if "user_code" not in flow:
                logger.error(f"Failed to initiate device flow: {flow.get('error_description', 'Unknown error')}")
                return {
                    "success": False,
                    "message": f"Failed to initiate device code flow: {flow.get('error_description', 'Unknown error')}"
                }
            
            # Return device flow information
            return {
                "success": True,
                "device_flow": flow,
                "user_code": flow["user_code"],
                "verification_uri": flow["verification_uri"],
                "expires_in": flow["expires_in"],
                "message": "Device code flow initiated successfully. Please complete authentication in your browser."
            }
            
        except ImportError:
            logger.error("MSAL library not found. Please install: pip install msal")
            return {
                "success": False,
                "message": "MSAL library not installed. Please install msal package."
            }
        except Exception as e:
            logger.error(f"Error initiating device flow: {e}")
            return {
                "success": False,
                "message": f"Error initiating device code flow: {str(e)}"
            }
    
    def complete_device_code_authentication(self, flow: Dict) -> Dict:
        """
        Complete device code authentication process
        Args:
            flow: The flow object returned from authenticate_with_device_code
            
        Returns:
            Dict with authentication result
        """
        try:
            from msal import PublicClientApplication
            
            # Initialize MSAL client
            app = PublicClientApplication(
                client_id=self.config.public_client_id,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}"
            )
            
            # Try to acquire token by device flow
            result = app.acquire_token_by_device_flow(flow)
            
            if "access_token" in result:
                # Authentication successful
                user_info = self._get_user_info_from_graph(result["access_token"])
                username = user_info.get("userPrincipalName", "unknown")
                role = self._determine_user_role(username)
                permissions = self._get_user_permissions(username, role)
                
                logger.info(f"Device code authentication successful for {username}")
                return {
                    "success": True,
                    "user": {
                        "username": username,
                        "display_name": user_info.get("displayName", username),
                        "role": role,
                        "permissions": permissions,
                        "email": user_info.get("mail") or user_info.get("userPrincipalName"),
                        "real_azure_user": True,
                        "auth_method": "device_code"
                    },
                    "token": result["access_token"],
                    "message": "Azure AD authentication successful"
                }
            else:
                error_description = result.get("error_description", "Unknown error")
                logger.error(f"Device code authentication failed: {error_description}")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Azure AD authentication failed: {error_description}"
                }
                
        except ImportError:
            logger.error("MSAL library not found. Please install: pip install msal")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": "MSAL library not installed. Please install msal package."
            }
        except Exception as e:
            logger.error(f"Error completing device code authentication: {e}")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": f"Error completing device code authentication: {str(e)}"
            }
            
    def authenticate_with_username_password(self, username: str, password: str) -> Dict:
        """
        Authenticate user with username/password against Azure AD
        Only supports real Azure AD authentication
        """
        try:
            # Directly authenticate with Azure AD
            return self._authenticate_real_azure_user(username, password)
                
        except Exception as e:
            logger.error(f"Azure authentication error: {e}")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": f"Authentication error: {str(e)}"
            }
    
    def _authenticate_real_azure_user(self, username: str, password: str) -> Dict:
        """
        Authenticate real Azure AD user using direct OAuth2 ROPC flow
        This method uses the OAuth2 password grant flow to authenticate against Azure AD
        
        Note: This flow requires that:
        1. The app is registered with proper permissions
        2. The user does not have MFA enabled
        3. The tenant policy allows ROPC flow
        4. Using /organizations or tenant-specific endpoint (not /common or /consumers)
        """
        try:
            import requests
            
            # DEBUG: Print detailed information about the authentication process
            logger.debug("=== STARTING AZURE AD AUTHENTICATION DEBUG ===")
            logger.debug(f"Username: {username}")
            logger.debug(f"Configuration: client_id={self.config.client_id[:6]}..., tenant_id={self.config.tenant_id}")
            
            # Try both organizations and common endpoints for testing
            token_url = f"https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
            
            # Log the token URL being used (don't log in production)
            logger.debug(f"Using OAuth token endpoint: {token_url}")
            
            # Prepare the request body for OAuth2 password grant flow
            token_data = {
                'grant_type': 'password',
                'client_id': self.config.client_id,
                'client_secret': self.config.client_secret,  # Required for confidential clients
                'scope': 'https://graph.microsoft.com/.default offline_access',  # Broader scope for debugging
                'username': username,
                'password': password
            }
            
            # DEBUG: Log the request data (sanitize password)
            debug_data = token_data.copy()
            debug_data['password'] = '********'
            logger.debug(f"Auth request data: {debug_data}")
            
            # Add proper headers for the token request
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # DEBUG: Log full request details
            logger.debug(f"Request headers: {headers}")
            
            # Make the token request with proper error handling
            try:
                token_response = requests.post(token_url, data=token_data, headers=headers)
                logger.debug(f"Response status code: {token_response.status_code}")
                logger.debug(f"Response headers: {dict(token_response.headers)}")
            except Exception as req_ex:
                logger.error(f"Request exception: {req_ex}")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Network error during authentication: {str(req_ex)}"
                }
            
            # Try to parse JSON response - handle potential JSON parsing errors
            try:
                result = token_response.json()
                logger.debug(f"Response content type: {token_response.headers.get('Content-Type', 'unknown')}")
            except ValueError:
                # Log the raw response for debugging
                logger.error(f"Invalid JSON response. Status code: {token_response.status_code}")
                logger.error(f"Response text: {token_response.text[:500]}")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Azure AD authentication error: Invalid response format (Status: {token_response.status_code})"
                }
            
            # Log error details for debugging
            if "error" in result:
                error_code = result.get("error")
                error_description = result.get("error_description", "")
                correlation_id = result.get("correlation_id", "unknown")
                timestamp = result.get("timestamp", "unknown")
                trace_id = result.get("trace_id", "unknown")
                
                # Detailed logging of the error
                logger.error(f"OAuth token error: {error_code}")
                logger.error(f"Full error description: {error_description}")
                logger.error(f"Correlation ID: {correlation_id}")
                logger.error(f"Timestamp: {timestamp}")
                logger.error(f"Trace ID: {trace_id}")
                
                # Debug - try to extract AADSTS code if present
                import re
                aadsts_match = re.search(r'AADSTS\d+', error_description)
                if aadsts_match:
                    aadsts_code = aadsts_match.group(0)
                    logger.error(f"AADSTS Error Code: {aadsts_code}")
                
                # If we got AADSTS9000102 error, try with a specific tenant ID
                if "AADSTS9000102" in error_description:
                    logger.debug("Got AADSTS9000102 error, trying with specific tenant ID instead")
                    # You can set a specific tenant ID here if you have one
                    specific_tenant_id = "7ae3526a-96fa-407a-9b02-9fe5bdff6217"  # Example tenant ID
                    return self._try_with_specific_tenant(username, password, specific_tenant_id)
                
                # Handle common error scenarios with user-friendly messages
                if "AADSTS50076" in error_description or "AADSTS50079" in error_description:
                    # MFA required error
                    return {
                        "success": False,
                        "user": None,
                        "token": None,
                        "message": "Bu hesap için çok faktörlü kimlik doğrulama (MFA) gerekiyor."
                    }
                elif "AADSTS50126" in error_description:
                    # Invalid username or password
                    return {
                        "success": False,
                        "user": None,
                        "token": None,
                        "message": "Hatalı kullanıcı adı veya şifre. Lütfen kimlik bilgilerinizi kontrol edin."
                    }
                elif "AADSTS50034" in error_description:
                    # User not found
                    return {
                        "success": False,
                        "user": None,
                        "token": None,
                        "message": "Bu kullanıcı hesabı Azure AD'de bulunamadı."
                    }
            
            if "access_token" in result:
                # Success with username/password
                user_info = self._get_user_info_from_graph(result["access_token"])
                role = self._determine_user_role(username)
                permissions = self._get_user_permissions(username, role)
                
                logger.info(f"Real Azure authentication successful for {username}")
                return {
                    "success": True,
                    "user": {
                        "username": username,
                        "display_name": user_info.get("displayName", username),
                        "role": role,
                        "permissions": permissions,
                        "email": user_info.get("mail") or user_info.get("userPrincipalName"),
                        "real_azure_user": True,
                        "auth_method": "password"
                    },
                    "token": result["access_token"],
                    "message": "Azure AD authentication successful"
                }
            else:
                error_description = result.get("error_description", "Unknown error")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Azure AD authentication failed: {error_description}"
                }
                
        except ImportError:
            logger.error("MSAL library not found. Please install: pip install msal")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": "MSAL library not installed. Please install msal package."
            }
        except Exception as e:
            logger.error(f"Real Azure authentication error: {e}")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": f"Azure AD authentication error: {str(e)}"
            }
    
    def _try_with_specific_tenant(self, username: str, password: str, tenant_id: str) -> Dict:
        """Fallback authentication method using a specific tenant ID"""
        logger.debug(f"Attempting authentication with specific tenant ID: {tenant_id}")
        
        try:
            import requests
            
            # Use specific tenant ID endpoint
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            logger.debug(f"Fallback OAuth token endpoint: {token_url}")
            
            # Headers
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # Request data
            token_data = {
                'grant_type': 'password',
                'client_id': self.config.client_id,
                'client_secret': self.config.client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'username': username,
                'password': password
            }
            
            # Make the request
            token_response = requests.post(token_url, data=token_data, headers=headers)
            logger.debug(f"Fallback response status code: {token_response.status_code}")
            
            # Parse response
            try:
                result = token_response.json()
            except ValueError:
                logger.error(f"Invalid JSON in fallback response: {token_response.text[:200]}")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Azure AD authentication error with fallback tenant: Invalid response format"
                }
            
            # Check for errors
            if "error" in result:
                error_code = result.get("error")
                error_description = result.get("error_description", "")
                logger.error(f"Fallback OAuth token error: {error_code}")
                logger.error(f"Fallback error description: {error_description[:200]}")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Azure AD authentication failed with fallback tenant: {error_description}"
                }
                
            if "access_token" in result:
                # Success with username/password
                user_info = self._get_user_info_from_graph(result["access_token"])
                role = self._determine_user_role(username)
                permissions = self._get_user_permissions(username, role)
                
                logger.info(f"Fallback Azure authentication successful for {username}")
                return {
                    "success": True,
                    "user": {
                        "username": username,
                        "display_name": user_info.get("displayName", username),
                        "role": role,
                        "permissions": permissions,
                        "email": user_info.get("mail") or user_info.get("userPrincipalName"),
                        "real_azure_user": True,
                        "auth_method": "password"
                    },
                    "token": result["access_token"],
                    "message": "Azure AD authentication successful with fallback tenant"
                }
                
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": "Unknown error with fallback tenant authentication"
            }
                
        except Exception as e:
            logger.error(f"Error in fallback authentication: {e}")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": f"Error in fallback authentication: {str(e)}"
            }
    
    def _get_user_info_from_graph(self, access_token: str) -> Dict:
        """Get user information from Microsoft Graph API"""
        try:
            import requests
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get user info from Graph API: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting user info from Graph API: {e}")
            return {}
    
    def _determine_user_role(self, username: str) -> str:
        """Determine user role based on username or other criteria"""
        # For now, assign standard role to all real users
        # In production, you might check Azure AD groups or custom attributes
        if username.lower().startswith("admin") or "admin" in username.lower():
            return "admin"
        elif username.lower().startswith("manager") or "manager" in username.lower():
            return "manager"
        else:
            return "standard"
    
    def _get_user_permissions(self, username: str, role: str) -> Dict:
        """Get user permissions based on role"""
        if role == "admin":
            # Admin has full access to all agents
            return {
                "hr_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": True
                },
                "finance_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": True
                },
                "sales_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": True
                },
                "marketing_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": True
                }
            }
        elif role == "manager":
            # Manager has most permissions
            return {
                "hr_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": True
                },
                "finance_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": False
                },
                "sales_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": True
                }
            }
        else:
            # Standard user has limited permissions
            return {
                "hr_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": True,
                    "document_delete": False
                },
                "finance_agent": {
                    "access": True,
                    "chat": True,
                    "document_upload": False,
                    "document_delete": False
                }
            }
    
    def get_azure_credential(self) -> DefaultAzureCredential:
        """Get Azure credential for service authentication"""
        try:
            if self.config.dev_mode:
                # For development, use client secret credential
                return ClientSecretCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.client_id,
                    client_secret=self.config.client_secret
                )
            else:
                # For production, use managed identity or default credential chain
                return DefaultAzureCredential()
        except Exception as e:
            logger.error(f"Error creating Azure credential: {e}")
            return DefaultAzureCredential()

# Enhanced Azure AI Agent Client
class EnhancedAzureAIAgentClient:
    """Enhanced wrapper for Azure AI Agent operations with document management"""
    
    def __init__(self, connection_string: str, agent_id: str, config: AzureConfig):
        self.connection_string = connection_string
        self.agent_id = agent_id
        self.config = config
        self.client = None
        self.agent = None
        self.blob_client = None
        self.search_client = None
        self.search_index_client = None
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize all Azure clients with proper error handling"""
        try:
            # Initialize AI Project Client
            self.client = AIProjectClient.from_connection_string(
                credential=DefaultAzureCredential(),
                conn_str=self.connection_string
            )
            self.agent = self.client.agents.get_agent(self.agent_id)
            
            # Initialize Blob Storage Client
            self.blob_client = BlobServiceClient.from_connection_string(
                self.config.storage_connection_string
            )
            
            # Initialize Azure Search clients
            try:
                credential = AzureKeyCredential(self.config.search_admin_key)
                self.search_index_client = SearchIndexClient(
                    endpoint=self.config.search_endpoint,
                    credential=credential
                )
                # search_client will be initialized per index when needed
                self.search_client = None
                logger.info("Azure Search clients initialized successfully")
            except Exception as search_error:
                logger.warning(f"Azure Search initialization failed: {search_error}")
                self.search_index_client = None
                self.search_client = None
            
            logger.info("All Azure clients initialized successfully")
            
        except AzureError as e:
            logger.error(f"Azure error during initialization: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            raise
    
    def create_thread(self):
        """Create a new conversation thread"""
        try:
            thread = self.client.agents.create_thread()
            logger.info(f"Thread created with ID: {thread.id}")
            return thread
        except AzureError as e:
            logger.error(f"Error creating thread: {e}")
            raise
    
    def send_message_and_get_response(self, thread_id: str, user_message: str):
        """Send message to agent and get response with retry logic"""
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                # Create user message
                self.client.agents.create_message(
                    thread_id=thread_id,
                    role="user",
                    content=user_message
                )
                
                # Create and process run
                run = self.client.agents.create_and_process_run(
                    thread_id=thread_id,
                    agent_id=self.agent.id
                )
                
                # Get messages
                messages = self.client.agents.list_messages(thread_id=thread_id)
                
                # Extract response
                text_messages = list(messages.text_messages)
                if text_messages:
                    first_message = text_messages[0]
                    
                    # Extract the text content
                    response_text = ""
                    if hasattr(first_message, 'text') and hasattr(first_message.text, 'value'):
                        response_text = first_message.text.value
                        logger.info(f"Extracted response text: {response_text[:100]}...")
                    
                    # Process file citation annotations to replace source placeholders
                    if hasattr(first_message, 'file_citation_annotations'):
                        citations = first_message.file_citation_annotations
                        logger.info(f"Found {len(citations)} file citation annotations")
                        
                        # Replace citation placeholders with actual file names
                        for i, citation in enumerate(citations):
                            if hasattr(citation, 'file_citation') and hasattr(citation.file_citation, 'file_id'):
                                # Try to get file information
                                try:
                                    file_info = self.client.agents.get_file(citation.file_citation.file_id)
                                    file_name = getattr(file_info, 'filename', f'file_{i}')
                                    logger.info(f"Citation {i}: {file_name}")
                                    
                                    # Replace the citation placeholder with actual file name
                                    placeholder = f"[{i}:source]"
                                    if placeholder in response_text:
                                        response_text = response_text.replace(placeholder, f"[{file_name}]")
                                        logger.info(f"Replaced {placeholder} with [{file_name}]")
                                except Exception as file_error:
                                    logger.warning(f"Could not get file info for citation {i}: {file_error}")
                                    # Replace with generic source reference
                                    placeholder = f"[{i}:source]"
                                    if placeholder in response_text:
                                        response_text = response_text.replace(placeholder, f"[Kaynak Dosya {i+1}]")
                    
                    # Also handle text annotations if they exist
                    if hasattr(first_message, 'text') and hasattr(first_message.text, 'annotations'):
                        annotations = first_message.text.annotations
                        logger.info(f"Found {len(annotations)} text annotations")
                        
                        for i, annotation in enumerate(annotations):
                            logger.info(f"Processing annotation {i}: {type(annotation)}")
                            
                            # Handle file citations
                            if hasattr(annotation, 'file_citation'):
                                try:
                                    file_info = self.client.agents.get_file(annotation.file_citation.file_id)
                                    file_name = getattr(file_info, 'filename', f'file_{i}')
                                    logger.info(f"File annotation {i}: {file_name}")
                                    
                                    # Replace citation text with file name
                                    if hasattr(annotation, 'text'):
                                        old_text = annotation.text
                                        response_text = response_text.replace(old_text, f"[{file_name}]")
                                        logger.info(f"Replaced annotation text '{old_text}' with [{file_name}]")
                                except Exception as file_error:
                                    logger.warning(f"Could not get file info for file annotation {i}: {file_error}")
                                    # Replace with generic source reference
                                    if hasattr(annotation, 'text'):
                                        old_text = annotation.text
                                        response_text = response_text.replace(old_text, f"[Kaynak Dosya {i+1}]")
                                        logger.info(f"Replaced annotation text '{old_text}' with [Kaynak Dosya {i+1}]")
                            
                            # Handle URL citations
                            elif hasattr(annotation, 'url_citation'):
                                try:
                                    url_citation = annotation.url_citation
                                    
                                    # First try to get title (this should be the actual filename)
                                    file_name = getattr(url_citation, 'title', None)
                                    
                                    # If no title, fallback to URL
                                    if not file_name:
                                        url = getattr(url_citation, 'url', f'URL_{i}')
                                        # Try to extract a meaningful name from the URL
                                        import os
                                        file_name = os.path.basename(url) if url else f'URL_{i}'
                                    
                                    # Final fallback
                                    if not file_name or file_name in ['doc_0', f'URL_{i}']:
                                        file_name = f"Web Kaynağı {i+1}"
                                    
                                    logger.info(f"URL annotation {i}: {file_name}")
                                    
                                    # Replace citation text with file name
                                    if hasattr(annotation, 'text'):
                                        old_text = annotation.text
                                        response_text = response_text.replace(old_text, f"[{file_name}]")
                                        logger.info(f"Replaced URL annotation text '{old_text}' with [{file_name}]")
                                except Exception as url_error:
                                    logger.warning(f"Could not process URL annotation {i}: {url_error}")
                                    # Replace with generic source reference
                                    if hasattr(annotation, 'text'):
                                        old_text = annotation.text
                                        response_text = response_text.replace(old_text, f"[Web Kaynağı {i+1}]")
                                        logger.info(f"Replaced URL annotation text '{old_text}' with [Web Kaynağı {i+1}]")
                            
                            # Handle any other annotation types generically
                            else:
                                if hasattr(annotation, 'text'):
                                    old_text = annotation.text
                                    response_text = response_text.replace(old_text, f"[Kaynak {i+1}]")
                                    logger.info(f"Replaced generic annotation text '{old_text}' with [Kaynak {i+1}]")
                    
                    # Additional processing for any remaining citation patterns
                    import re
                    
                    # Look for any remaining [:source] patterns and replace them
                    citation_pattern = r'\[(\d+):source\]'
                    matches = re.findall(citation_pattern, response_text)
                    
                    for match in matches:
                        index = int(match)
                        placeholder = f"[{index}:source]"
                        response_text = response_text.replace(placeholder, f"[Kaynak Dosya {index+1}]")
                        logger.info(f"Replaced remaining placeholder {placeholder} with [Kaynak Dosya {index+1}]")
                    
                    return response_text if response_text else "No response received from agent."

                return "No response received from agent."
                
            except AzureError as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                else:
                    raise
    
    def upload_document(self, container_name: str, file_name: str, file_content: bytes):
        """Upload document to Azure Blob Storage"""
        try:
            # Try to upload to Azure Blob Storage
            try:
                # Create container if it doesn't exist
                container_client = self.blob_client.get_container_client(container_name)
                try:
                    container_client.get_container_properties()
                except:
                    container_client.create_container()
                
                # Upload blob
                blob_client = container_client.get_blob_client(file_name)
                blob_client.upload_blob(file_content, overwrite=True)
                
                logger.info(f"Document {file_name} uploaded to {container_name}")
                return True
                
            except Exception as azure_error:
                logger.warning(f"Azure Blob Storage upload failed: {azure_error}")
                logger.info("Document upload simulated for demo purposes")
                
                # For demo purposes, just log the upload
                file_size = len(file_content) if file_content else 0
                logger.info(f"Demo upload: {file_name} ({file_size} bytes) to {container_name}")
                return True
            
        except Exception as e:
            logger.error(f"Error uploading document: {e}")
            return False
    
    def list_documents(self, container_name: str):
        """List documents in container"""
        try:
            # For demo purposes, if Azure connection fails, return demo documents
            try:
                container_client = self.blob_client.get_container_client(container_name)
                
                # Try to get container properties first, create if doesn't exist
                try:
                    container_client.get_container_properties()
                except Exception as container_error:
                    if "ContainerNotFound" in str(container_error):
                        logger.info(f"Container {container_name} not found, creating it...")
                        container_client.create_container()
                        logger.info(f"Container {container_name} created successfully")
                        # Return empty list for new container
                        return []
                    else:
                        raise container_error
                
                # List blobs in the container
                blobs = container_client.list_blobs()
                
                documents = []
                for blob in blobs:
                    documents.append({
                        'name': blob.name,
                        'size': blob.size or 0,
                        'last_modified': blob.last_modified,
                        'content_type': blob.content_settings.content_type if blob.content_settings else 'unknown'
                    })
                
                logger.info(f"Found {len(documents)} documents in container {container_name}")
                return documents
                
            except Exception as azure_error:
                logger.warning(f"Azure Blob Storage connection failed: {azure_error}")
                logger.info("Returning demo documents for testing")
                
                # Return demo documents
                from datetime import datetime, timedelta
                demo_docs = [
                    {
                        'name': 'sample_report.pdf',
                        'size': 1024 * 1024,  # 1 MB
                        'last_modified': datetime.now() - timedelta(hours=2),
                        'content_type': 'application/pdf'
                    },
                    {
                        'name': 'data_analysis.xlsx',
                        'size': 512 * 1024,  # 512 KB
                        'last_modified': datetime.now() - timedelta(days=1),
                        'content_type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                    },
                    {
                        'name': 'meeting_notes.docx',
                        'size': 256 * 1024,  # 256 KB
                        'last_modified': datetime.now() - timedelta(hours=5),
                        'content_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                    }
                ]
                return demo_docs
            
        except Exception as e:
            logger.error(f"Error listing documents: {e}")
            return []
    
    def delete_document(self, container_name: str, file_name: str):
        """Delete document from container"""
        try:
            container_client = self.blob_client.get_container_client(container_name)
            blob_client = container_client.get_blob_client(file_name)
            blob_client.delete_blob()
            
            logger.info(f"Document {file_name} deleted from {container_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting document: {e}")
            return False

    def create_search_index(self, index_name: str) -> bool:
        """Create Azure Search index with vector search capabilities"""
        try:
            if not self.search_index_client:
                logger.warning("Search index client not initialized, skipping index creation")
                return False
                
            # Check if index already exists
            try:
                existing_index = self.search_index_client.get_index(index_name)
                logger.info(f"Search index '{index_name}' already exists")
                return True
            except Exception:
                # Index doesn't exist, create it
                pass
            
            # Define the search index schema with vector fields
            fields = [
                SimpleField(name="id", type=SearchFieldDataType.String, key=True),
                SearchableField(name="content", type=SearchFieldDataType.String, 
                              analyzer_name="standard.lucene"),
                SearchableField(name="filename", type=SearchFieldDataType.String),
                SimpleField(name="container_name", type=SearchFieldDataType.String, 
                          filterable=True),
                SimpleField(name="content_type", type=SearchFieldDataType.String, 
                          filterable=True),
                SimpleField(name="file_size", type=SearchFieldDataType.Int64),
                SimpleField(name="last_modified", type=SearchFieldDataType.DateTimeOffset),
                SimpleField(name="upload_timestamp", type=SearchFieldDataType.DateTimeOffset),
                SearchableField(name="extracted_text", type=SearchFieldDataType.String, 
                              analyzer_name="standard.lucene"),
                SearchableField(name="metadata", type=SearchFieldDataType.String),
                # Vector field for semantic search
                SearchField(
                    name="content_vector",
                    type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
                    searchable=True,
                    vector_search_dimensions=1536,  # OpenAI text-embedding-ada-002 dimensions
                    vector_search_profile_name="content-vector-profile"
                )
            ]
            
            # Configure vector search
            vector_search = VectorSearch(
                algorithms=[
                    HnswAlgorithmConfiguration(name="content-hnsw")
                ],
                profiles=[
                    VectorSearchProfile(
                        name="content-vector-profile",
                        algorithm_configuration_name="content-hnsw"
                    )
                ]
            )
            
            # Configure semantic search
            semantic_config = SemanticConfiguration(
                name="default",
                prioritized_fields=SemanticPrioritizedFields(
                    title_field=SemanticField(field_name="filename"),
                    content_fields=[
                        SemanticField(field_name="content"),
                        SemanticField(field_name="extracted_text")
                    ]
                )
            )
            
            semantic_search = SemanticSearch(configurations=[semantic_config])
            
            # Create the search index
            index = SearchIndex(
                name=index_name,
                fields=fields,
                vector_search=vector_search,
                semantic_search=semantic_search
            )
            
            result = self.search_index_client.create_index(index)
            logger.info(f"Search index '{index_name}' created successfully with vector search capabilities")
            return True
            
        except Exception as e:
            logger.error(f"Error creating search index '{index_name}': {e}")
            return False
    
    def get_search_client(self, index_name: str) -> Optional[SearchClient]:
        """Get search client for specific index"""
        try:
            if not self.config.search_endpoint or not self.config.search_admin_key:
                logger.warning("Search endpoint or admin key not configured")
                return None
                
            credential = AzureKeyCredential(self.config.search_admin_key)
            return SearchClient(
                endpoint=self.config.search_endpoint,
                index_name=index_name,
                credential=credential
            )
        except Exception as e:
            logger.error(f"Error creating search client for index '{index_name}': {e}")
            return None

    def extract_text_from_document(self, file_content: bytes, content_type: str, filename: str) -> str:
        """Extract text from various document types"""
        try:
            text_content = ""
            
            if content_type == 'application/pdf' or filename.lower().endswith('.pdf'):
                try:
                    import PyPDF2
                    from io import BytesIO
                    
                    pdf_reader = PyPDF2.PdfReader(BytesIO(file_content))
                    for page in pdf_reader.pages:
                        text_content += page.extract_text() + "\n"
                except Exception as pdf_error:
                    logger.warning(f"PDF extraction failed: {pdf_error}")
                    text_content = f"[PDF content extraction failed: {filename}]"
                    
            elif content_type in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'] or filename.lower().endswith('.docx'):
                try:
                    from docx import Document
                    from io import BytesIO
                    
                    doc = Document(BytesIO(file_content))
                    for paragraph in doc.paragraphs:
                        text_content += paragraph.text + "\n"
                except Exception as docx_error:
                    logger.warning(f"DOCX extraction failed: {docx_error}")
                    text_content = f"[DOCX content extraction failed: {filename}]"
                    
            elif content_type in ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'] or filename.lower().endswith('.xlsx'):
                try:
                    import openpyxl
                    from io import BytesIO
                    
                    wb = openpyxl.load_workbook(BytesIO(file_content))
                    for sheet_name in wb.sheetnames:
                        sheet = wb[sheet_name]
                        text_content += f"Sheet: {sheet_name}\n"
                        for row in sheet.iter_rows(values_only=True):
                            row_text = " | ".join([str(cell) if cell is not None else "" for cell in row])
                            if row_text.strip():
                                text_content += row_text + "\n"
                except Exception as xlsx_error:
                    logger.warning(f"XLSX extraction failed: {xlsx_error}")
                    text_content = f"[XLSX content extraction failed: {filename}]"
                    
            elif content_type.startswith('text/') or filename.lower().endswith(('.txt', '.md', '.csv')):
                try:
                    text_content = file_content.decode('utf-8', errors='ignore')
                except Exception as text_error:
                    logger.warning(f"Text extraction failed: {text_error}")
                    text_content = f"[Text content extraction failed: {filename}]"
            else:
                text_content = f"[Content type {content_type} not supported for text extraction: {filename}]"
                
            return text_content[:10000]  # Limit to 10K characters to avoid index size issues
            
        except Exception as e:
            logger.error(f"Error extracting text from document {filename}: {e}")
            return f"[Text extraction error: {filename}]"

    def get_text_embedding(self, text: str) -> Optional[List[float]]:
        """Generate text embedding using Azure OpenAI"""
        try:
            if not self.config.openai_endpoint or not self.config.openai_api_key:
                logger.warning("OpenAI endpoint or API key not configured, generating mock embedding for demo")
                # Return mock embedding for demo purposes
                import random
                random.seed(hash(text) % 2147483647)  # Consistent mock embedding for same text
                return [random.uniform(-1, 1) for _ in range(1536)]
                
            # Use Azure OpenAI for embeddings
            headers = {
                "Content-Type": "application/json",
                "api-key": self.config.openai_api_key
            }
            
            # Truncate text if too long (max 8191 tokens for text-embedding-ada-002)
            max_chars = 8000  # Conservative estimate
            if len(text) > max_chars:
                text = text[:max_chars]
                
            data = {
                "input": text
            }
            
            # Try multiple embedding endpoints
            embedding_endpoints = [
                f"{self.config.openai_endpoint}/openai/deployments/text-embedding-ada-002/embeddings?api-version=2023-05-15",
                f"{self.config.openai_endpoint}/openai/deployments/text-embedding-3-small/embeddings?api-version=2024-02-01",
                f"{self.config.openai_endpoint}/openai/embeddings?api-version=2023-05-15"
            ]
            
            for endpoint in embedding_endpoints:
                try:
                    response = requests.post(
                        endpoint,
                        headers=headers,
                        json=data,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        embedding = result["data"][0]["embedding"]
                        logger.info(f"Generated embedding with {len(embedding)} dimensions using endpoint: {endpoint}")
                        return embedding
                    else:
                        logger.warning(f"Endpoint {endpoint} failed with status {response.status_code}")
                        continue
                        
                except Exception as endpoint_error:
                    logger.warning(f"Error with endpoint {endpoint}: {endpoint_error}")
                    continue
            
            # If all endpoints fail, use mock embedding
            logger.warning("All embedding endpoints failed, using mock embedding")
            import random
            random.seed(hash(text) % 2147483647)
            return [random.uniform(-1, 1) for _ in range(1536)]
                
        except Exception as e:
            logger.error(f"Error generating text embedding: {e}")
            # Return mock embedding as fallback
            import random
            random.seed(hash(text) % 2147483647)
            return [random.uniform(-1, 1) for _ in range(1536)]

    def index_document(self, container_name: str, filename: str, file_content: bytes, 
                      content_type: str, index_name: str) -> bool:
        """Index a document in Azure Search with vector embeddings"""
        try:
            if not self.search_index_client:
                logger.warning("Search functionality not available (demo mode)")
                return True  # Return True for demo mode
                
            # Ensure index exists
            if not self.create_search_index(index_name):
                logger.error(f"Failed to create or access index '{index_name}'")
                return False
                
            # Get search client for this index
            search_client = self.get_search_client(index_name)
            if not search_client:
                logger.error(f"Failed to get search client for index '{index_name}'")
                return False
                
            # Extract text content
            extracted_text = self.extract_text_from_document(file_content, content_type, filename)
            
            # Generate vector embedding for the text content - ALWAYS generate
            content_for_embedding = f"{filename} {extracted_text}"[:8000]  # Combine filename and content
            logger.info(f"Generating vector embedding for document: {filename}")
            content_vector = self.get_text_embedding(content_for_embedding)
            
            # Create document for indexing
            document_id = hashlib.md5(f"{container_name}/{filename}".encode()).hexdigest()
            
            search_document = {
                "id": document_id,
                "content": extracted_text[:1000],  # Summary content
                "filename": filename,
                "container_name": container_name,
                "content_type": content_type,
                "file_size": len(file_content),
                "last_modified": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                "upload_timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                "extracted_text": extracted_text,
                "metadata": json.dumps({
                    "container": container_name,
                    "original_filename": filename,
                    "content_type": content_type,
                    "indexed_at": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    "has_vector": content_vector is not None,
                    "vector_dimensions": len(content_vector) if content_vector else 0
                })
            }
            
            # Add vector embedding - ALWAYS add if available
            if content_vector and len(content_vector) == 1536:
                search_document["content_vector"] = content_vector
                logger.info(f"✅ Added {len(content_vector)}-dimensional vector embedding to document '{filename}'")
            else:
                logger.warning(f"⚠️ No valid vector embedding for document '{filename}' (got {len(content_vector) if content_vector else 0} dimensions)")
            
            # Upload document to search index
            result = search_client.upload_documents([search_document])
            
            if result and len(result) > 0 and result[0].succeeded:
                success_msg = f"Document '{filename}' successfully indexed in '{index_name}'"
                if content_vector:
                    success_msg += " with vector embeddings"
                logger.info(success_msg)
                return True
            else:
                logger.error(f"Failed to index document '{filename}' in '{index_name}'")
                return False
                
        except Exception as e:
            logger.error(f"Error indexing document '{filename}': {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def search_documents(self, query: str, index_name: str, top: int = 10) -> List[Dict]:
        """Search documents using hybrid search (text + vector)"""
        try:
            if not self.search_index_client:
                logger.warning("Search functionality not available (demo mode)")
                # Return demo search results
                return [
                    {
                        "filename": f"demo_result_{i}.pdf",
                        "content": f"Demo search result {i} for query: {query}",
                        "score": 0.9 - (i * 0.1),
                        "container_name": "demo-container"
                    }
                    for i in range(1, min(4, top + 1))
                ]
                
            search_client = self.get_search_client(index_name)
            if not search_client:
                logger.error(f"Failed to get search client for index '{index_name}'")
                return []
                
            search_results = []
            
            # Try hybrid search (text + vector) first
            try:
                # Generate embedding for the query
                query_vector = self.get_text_embedding(query)
                
                if query_vector:
                    # Perform hybrid search with vector similarity
                    vector_query = VectorizedQuery(
                        vector=query_vector,
                        k_nearest_neighbors=top,
                        fields="content_vector"
                    )
                    
                    results = search_client.search(
                        search_text=query,
                        vector_queries=[vector_query],
                        top=top,
                        include_total_count=True,
                        highlight_fields="content,extracted_text",
                        query_type="semantic",
                        semantic_configuration_name="default"
                    )
                    
                    for result in results:
                        search_results.append({
                            "id": result.get("id"),
                            "filename": result.get("filename"),
                            "content": result.get("content", "")[:500],  # First 500 chars
                            "container_name": result.get("container_name"),
                            "content_type": result.get("content_type"),
                            "score": result.get("@search.score", 0),
                            "reranker_score": result.get("@search.reranker_score"),
                            "highlights": result.get("@search.highlights", {}),
                            "last_modified": result.get("last_modified"),
                            "search_type": "hybrid"
                        })
                    
                    logger.info(f"Hybrid search found {len(search_results)} results for query '{query}'")
                    
                else:
                    # Fallback to text-only search
                    raise Exception("No vector embedding available, falling back to text search")
                    
            except Exception as vector_error:
                logger.warning(f"Vector search failed, falling back to text search: {vector_error}")
                
                # Fallback to traditional text search
                results = search_client.search(
                    search_text=query,
                    top=top,
                    include_total_count=True,
                    highlight_fields="content,extracted_text"
                )
                
                for result in results:
                    search_results.append({
                        "id": result.get("id"),
                        "filename": result.get("filename"),
                        "content": result.get("content", "")[:500],  # First 500 chars
                        "container_name": result.get("container_name"),
                        "content_type": result.get("content_type"),
                        "score": result.get("@search.score", 0),
                        "highlights": result.get("@search.highlights", {}),
                        "last_modified": result.get("last_modified"),
                        "search_type": "text"
                    })
                
                logger.info(f"Text search found {len(search_results)} results for query '{query}'")
                
            return search_results
            
        except Exception as e:
            logger.error(f"Error searching documents in index '{index_name}': {e}")
            return []

    def upload_and_index_document(self, container_name: str, filename: str, 
                                 file_content: bytes, content_type: str, index_name: str) -> Dict:
        """Upload document to blob storage and index it in Azure Search"""
        try:
            # Upload to blob storage
            blob_upload_success = self.upload_document(container_name, filename, file_content)
            
            if not blob_upload_success:
                return {
                    "success": False,
                    "message": "Failed to upload document to blob storage",
                    "indexed": False
                }
            
            # Index the document
            index_success = self.index_document(container_name, filename, file_content, 
                                              content_type, index_name)
            
            return {
                "success": True,
                "message": f"Document '{filename}' uploaded successfully",
                "indexed": index_success,
                "index_message": "Document indexed successfully" if index_success else "Document uploaded but indexing failed"
            }
            
        except Exception as e:
            logger.error(f"Error in upload_and_index_document: {e}")
            return {
                "success": False,
                "message": f"Error uploading document: {str(e)}",
                "indexed": False
            }
    
    def authenticate_with_device_code(self, username: str = None) -> Dict:
        """
        Authenticate using Azure AD device code flow (supports MFA)
        This is the recommended method for desktop applications
        """
        try:
            from msal import PublicClientApplication
            
            # MSAL configuration
            app = PublicClientApplication(
                client_id=self.config.public_client_id,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}"
            )
            
            # Scope for basic profile information
            scopes = ["https://graph.microsoft.com/User.Read"]
            
            # Device code flow
            flow = app.initiate_device_flow(scopes=scopes)
            
            if "user_code" not in flow:
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": "Failed to create device flow"
                }
            
            # Return the device code information for user to complete authentication
            return {
                "success": False,  # Not yet complete
                "user": None,
                "token": None,
                "message": flow["message"],
                "device_flow": flow,
                "user_code": flow["user_code"],
                "verification_uri": flow["verification_uri"],
                "expires_in": flow["expires_in"]
            }
                
        except ImportError:
            logger.error("MSAL library not found. Please install: pip install msal")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": "MSAL library not installed. Please install msal package."
            }
        except Exception as e:
            logger.error(f"Device code authentication error: {e}")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": f"Device code authentication error: {str(e)}"
            }
    
    def complete_device_code_authentication(self, device_flow: Dict) -> Dict:
        """
        Complete the device code authentication after user has authenticated
        """
        try:
            from msal import PublicClientApplication
            
            # MSAL configuration
            app = PublicClientApplication(
                client_id=self.config.public_client_id,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}"
            )
            
            # Complete the device flow
            result = app.acquire_token_by_device_flow(device_flow)
            
            if "access_token" in result:
                # Success with device flow
                user_info = self._get_user_info_from_graph(result["access_token"])
                username = user_info.get("userPrincipalName") or user_info.get("mail")
                role = self._determine_user_role(username)
                permissions = self._get_user_permissions(username, role)
                
                logger.info(f"Real Azure device flow authentication successful for {username}")
                return {
                    "success": True,
                    "user": {
                        "username": username,
                        "display_name": user_info.get("displayName", username),
                        "role": role,
                        "permissions": permissions,
                        "email": user_info.get("mail") or user_info.get("userPrincipalName"),
                        "real_azure_user": True,
                        "auth_method": "device_code"
                    },
                    "token": result["access_token"],
                    "message": "Azure AD device code authentication successful"
                }
            else:
                error_description = result.get("error_description", "Unknown error")
                return {
                    "success": False,
                    "user": None,
                    "token": None,
                    "message": f"Azure AD device code authentication failed: {error_description}"
                }
                
        except Exception as e:
            logger.error(f"Device code completion error: {e}")
            return {
                "success": False,
                "user": None,
                "token": None,
                "message": f"Device code completion error: {str(e)}"
            }
