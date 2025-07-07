"""
Azure AI Agent Streamlit Chatbot
A modern chatbot interface using Azure AI Projects and Streamlit
"""

import streamlit as st
import time
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import AzureError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Azure AI Agent Chatbot",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #0078d4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .user-message {
        background-color: #e3f2fd;
        border-left: 4px solid #2196f3;
    }
    .assistant-message {
        background-color: #f3e5f5;
        border-left: 4px solid #9c27b0;
    }
    .error-message {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        color: #c62828;
    }
</style>
""", unsafe_allow_html=True)

class AzureAIAgentClient:
    """Wrapper class for Azure AI Agent operations with error handling and retry logic"""
    
    def __init__(self, connection_string: str, agent_id: str):
        self.connection_string = connection_string
        self.agent_id = agent_id
        self.client = None
        self.agent = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Azure AI Project Client with proper error handling"""
        try:
            self.client = AIProjectClient.from_connection_string(
                credential=DefaultAzureCredential(),
                conn_str=self.connection_string
            )
            logger.info("Azure AI Project Client initialized successfully")
            
            # Get the agent
            self.agent = self.client.agents.get_agent(self.agent_id)
            logger.info(f"Agent {self.agent_id} retrieved successfully")
            
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
                
                # Extract response from text_messages
                try:
                    # The text_messages contains MessageTextContent objects
                    text_messages = list(messages.text_messages)
                    
                    if text_messages:
                        # Get the first message (most recent assistant response)
                        first_message = text_messages[0]
                        
                        # Extract the text content
                        response_text = ""
                        if hasattr(first_message, 'text') and hasattr(first_message.text, 'value'):
                            response_text = first_message.text.value
                            logger.info(f"Extracted response text: {response_text[:100]}...")
                        else:
                            # Fallback: try as_dict approach
                            message_dict = first_message.as_dict()
                            text_content = message_dict.get('text', {})
                            if text_content and 'value' in text_content:
                                response_text = text_content['value']
                        
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
                            
                except Exception as parse_error:
                    logger.error(f"Error parsing messages: {parse_error}")
                
                return "No response received from agent."
                
            except AzureError as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                else:
                    raise
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                raise

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "thread_id" not in st.session_state:
        st.session_state.thread_id = None
    if "ai_client" not in st.session_state:
        st.session_state.ai_client = None
    if "connection_established" not in st.session_state:
        st.session_state.connection_established = False
    if "auto_connect_attempted" not in st.session_state:
        st.session_state.auto_connect_attempted = False

def auto_connect_to_agent():
    """Automatically connect to agent using default values"""
    if st.session_state.auto_connect_attempted or st.session_state.connection_established:
        return
    
    # Default connection values
    default_conn_str = "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject"
    default_agent_id = "asst_mEUu1oKSR4BUujGTR3kMj6Qw"
    
    st.session_state.auto_connect_attempted = True
    
    try:
        with st.spinner("🔄 Automatically connecting to Azure AI Agent..."):
            st.session_state.ai_client = AzureAIAgentClient(default_conn_str, default_agent_id)
            thread = st.session_state.ai_client.create_thread()
            st.session_state.thread_id = thread.id
            st.session_state.connection_established = True
        
        st.success("✅ Automatically connected to Azure AI Agent!")
        logger.info("Auto-connection to Azure AI Agent successful")
        
    except Exception as e:
        logger.error(f"Auto-connection failed: {e}")
        st.warning("⚠️ Auto-connection failed. Please use manual connection in the sidebar.")
        st.session_state.connection_established = False

def main():
    """Main Streamlit application"""
    
    # Initialize session state
    initialize_session_state()
    
    # Auto-connect to agent on first load
    auto_connect_to_agent()
    
    # Header
    st.markdown('<h1 class="main-header">🤖 Azure AI Agent Chatbot</h1>', unsafe_allow_html=True)
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Auto-connection status
        if st.session_state.connection_established:
            st.success("🤖 Auto-connected to Agent")
        elif st.session_state.auto_connect_attempted:
            st.info("🔄 Auto-connection attempted - Use manual settings below")
        else:
            st.info("🚀 Auto-connecting...")
        
        st.divider()
        
        # Manual connection section
        with st.expander("🔧 Manual Connection Settings", expanded=not st.session_state.connection_established):
            # Connection string input
            conn_str = st.text_input(
                "Azure AI Connection String",
                value="eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject",
                type="password",
                help="Enter your Azure AI Project connection string"
            )
            
            # Agent ID input
            agent_id = st.text_input(
                "Agent ID",
                value="asst_mEUu1oKSR4BUujGTR3kMj6Qw",
                help="Enter your Azure AI Agent ID"
            )
            
            # Connect button
            if st.button("🔗 Connect to Agent", type="primary"):
                if conn_str and agent_id:
                    try:
                        with st.spinner("Connecting to Azure AI Agent..."):
                            st.session_state.ai_client = AzureAIAgentClient(conn_str, agent_id)
                            thread = st.session_state.ai_client.create_thread()
                            st.session_state.thread_id = thread.id
                            st.session_state.connection_established = True
                        st.success("✅ Connected successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Connection failed: {str(e)}")
                        st.session_state.connection_established = False
                else:
                    st.error("Please provide both connection string and agent ID")
        
        # Connection status
        if st.session_state.connection_established:
            st.success("🟢 Connected")
            if st.button("🔄 New Conversation"):
                st.session_state.messages = []
                if st.session_state.ai_client:
                    thread = st.session_state.ai_client.create_thread()
                    st.session_state.thread_id = thread.id
                st.rerun()
        else:
            st.error("🔴 Not Connected")
        
        # Info section
        with st.expander("ℹ️ About"):
            st.markdown("""
            This chatbot uses Azure AI Projects to provide intelligent responses.
            
            **Features:**
            - 🚀 **Auto-connection** on startup
            - Secure authentication with Azure Identity
            - Persistent conversation threads
            - Error handling and retry logic
            - Modern UI with Streamlit
            
            **Auto-Connection:**
            The app automatically connects to the Azure AI Agent when you first load it.
            If auto-connection fails, you can use manual connection settings above.
            
            **Requirements:**
            - Valid Azure AI Project connection string
            - Valid Agent ID
            - Proper Azure authentication
            """)
    
    # Main chat interface
    if not st.session_state.connection_established:
        if not st.session_state.auto_connect_attempted:
            st.info("🚀 Auto-connecting to Azure AI Agent...")
        else:
            st.info("👈 Auto-connection failed. Please configure and connect manually using the sidebar.")
        return
    
    # Display chat messages
    chat_container = st.container()
    with chat_container:
        for message in st.session_state.messages:
            if message["role"] == "user":
                st.markdown(f"""
                <div class="chat-message user-message">
                    <strong>👤 You:</strong><br>
                    {message["content"]}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="chat-message assistant-message">
                    <strong>🤖 Assistant:</strong><br>
                    {message["content"]}
                </div>
                """, unsafe_allow_html=True)
    
    # Chat input
    user_input = st.chat_input("Type your message here...", key="chat_input")
    
    if user_input:
        # Add user message to chat
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        # Get AI response
        try:
            with st.spinner("🤔 Agent is thinking..."):
                response = st.session_state.ai_client.send_message_and_get_response(
                    st.session_state.thread_id, 
                    user_input
                )
            
            # Add assistant response to chat
            st.session_state.messages.append({"role": "assistant", "content": response})
            
        except Exception as e:
            error_msg = f"Error getting response: {str(e)}"
            st.error(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})
        
        # Rerun to update the chat display
        st.rerun()

if __name__ == "__main__":
    main()
