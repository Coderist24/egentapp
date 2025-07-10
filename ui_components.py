"""
UI Components for Multi-Agent Azure AI Platform
Contains all the user interface functions and components
"""

import streamlit as st
import pandas as pd
import os
from datetime import datetime
from typing import Dict, List

# Corporate process icons for agent selection
CORPORATE_ICONS = {
    "📊": "İstatistik & Raporlama",
    "📈": "Satış & Büyüme", 
    "📋": "Proje Yönetimi",
    "⚖️": "Hukuk & Uyumluluk",
    "💼": "İş Geliştirme",
    "🏭": "Üretim & Operasyon",
    "🔧": "Teknik Destek",
    "👥": "İnsan Kaynakları",
    "💰": "Finans & Muhasebe",
    "📦": "Tedarik Zinciri",
    "🎯": "Kalite Yönetimi",
    "🌐": "IT & Teknoloji",
    "📢": "Pazarlama & İletişim",
    "🛡️": "Güvenlik & Risk",
    "🔍": "Araştırma & Geliştirme",
    "📚": "Eğitim & Geliştirme",
    "🏢": "Kurumsal Yönetim",
    "📞": "Müşteri Hizmetleri",
    "📄": "Dokümantasyon",
    "⚙️": "Sistem Yönetimi"
}

def show_icon_selector(default_icon: str = "🤖", key: str = "icon_selector", use_radio: bool = False) -> str:
    """Display an icon selector with corporate process icons (form-compatible)"""
    st.write("**🎯 Ajan İkonu Seçin:**")
    st.write("*Kurumsal süreçlere uygun ikonlar arasından seçim yapın:*")
    
    # Create options for selectbox/radio (icon + description)
    icon_options = []
    icon_mapping = {}
    
    for icon, description in CORPORATE_ICONS.items():
        option_text = f"{icon} - {description}"
        icon_options.append(option_text)
        icon_mapping[option_text] = icon
    
    # Find current selection index
    current_selection_text = None
    for option_text, icon in icon_mapping.items():
        if icon == default_icon:
            current_selection_text = option_text
            break
    
    # If default icon not in predefined list, add it as custom option
    if current_selection_text is None:
        custom_option = f"{default_icon} - Özel İkon"
        icon_options.insert(0, custom_option)
        icon_mapping[custom_option] = default_icon
        current_selection_text = custom_option
    
    # Choose input method based on parameter
    if use_radio:
        # Use radio buttons (better for forms, more visual)
        selected_option = st.radio(
            "İkon Seçin:",
            options=icon_options,
            index=icon_options.index(current_selection_text) if current_selection_text in icon_options else 0,
            key=f"{key}_radio",
            help="Kurumsal süreçlere uygun ikonlar arasından seçim yapın",
            horizontal=False
        )
    else:
        # Use selectbox (more compact)
        selected_option = st.selectbox(
            "İkon Seçin:",
            options=icon_options,
            index=icon_options.index(current_selection_text) if current_selection_text in icon_options else 0,
            key=f"{key}_selectbox",
            help="Kurumsal süreçlere uygun ikonlar arasından seçim yapın"
        )
    
    # Get the selected icon
    selected_icon = icon_mapping.get(selected_option, default_icon)
    
    # Display selected icon preview
    st.markdown(f"""
    <div style='background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); 
                border-radius: 10px; padding: 1rem; margin: 1rem 0; 
                border-left: 4px solid #2196f3; text-align: center;'>
        <h3>Seçili İkon: {selected_icon}</h3>
        <p><em>{selected_option.split(' - ')[1] if ' - ' in selected_option else 'Özel İkon'}</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    # Also allow manual entry for custom icons
    with st.expander("🔧 Özel İkon Gir (İsteğe Bağlı)"):
        manual_icon = st.text_input("Özel emoji veya ikon:", 
                                   value=selected_icon, 
                                   key=f"{key}_manual",
                                   help="İstediğiniz emoji'yi buraya yazabilirsiniz (örn: 🚀, 💡, ⭐)")
        if manual_icon and manual_icon != selected_icon:
            selected_icon = manual_icon
    
    return selected_icon

def show_login_page():
    """Display the login page with two authentication options"""
    
    st.markdown('<h1 class="main-header">🤖 Azure Multi-Agent AI Platform</h1>', 
                unsafe_allow_html=True)
    
    # Login container
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div class="login-container">
            <h2 style="text-align: center; margin-bottom: 2rem;">🔐 Login</h2>
        """, unsafe_allow_html=True)
        
        # Login method selection
        login_method = st.radio(
            "Choose login method:",
            ["🔑 Admin Login", "☁️ Azure User Login"],
            index=1,  # Default to Azure User Login (index 1)
            horizontal=True
        )
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Login forms
        if login_method == "🔑 Admin Login":
            with st.form("admin_login"):
                st.subheader("Admin Login")
                username = st.text_input("Username", placeholder="admin")
                password = st.text_input("Password", type="password", placeholder="Password")
                
                submitted = st.form_submit_button("Login as Admin", type="primary")
                
                if submitted:
                    if st.session_state.user_manager.authenticate_admin(username, password):
                        st.session_state.authenticated = True
                        st.session_state.current_user = username
                        st.session_state.user_role = "admin"
                        st.session_state.current_page = "dashboard"
                        st.success("✅ Admin login successful!")
                        st.rerun()
                    else:
                        st.error("❌ Invalid admin credentials")
        
        else:  # Azure User Login
            # MFA destekli Azure AD Login (OAuth2 Authorization Code Flow)
            st.subheader("Azure AD Login (MFA Destekli)")
            st.info("☁️ Microsoft ile güvenli giriş için aşağıdaki bağlantıyı kullanın.")

            # MSAL ayarları - environment variables'dan al
            import msal
            import requests
            import os
            import urllib.parse
            
            # Azure Web App environment'da bu değerler Application Settings'de olmalı
            CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "c7790b94-d830-4746-961f-8c715a380c5e")
            TENANT_ID = os.environ.get("AZURE_TENANT_ID", "7ae3526a-96fa-407a-9b02-9fe5bdff6217")
            CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "6Jl8Q~Kue3BfEbXdbc3O-68WVEIPZeNFD-Bkub2p")
            
            # Redirect URI'yi dinamik olarak belirle
            if "WEBSITE_SITE_NAME" in os.environ:
                REDIRECT_URI = "https://egentapp-b4gqeudnc3h8emd3.westeurope-01.azurewebsites.net/"
            else:
                REDIRECT_URI = "http://localhost:8502"
            
            AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
            SCOPE = ["User.Read"]

            try:
                app = msal.ConfidentialClientApplication(
                    CLIENT_ID,
                    authority=AUTHORITY,
                    client_credential=CLIENT_SECRET
                )

                # Login URL oluştur
                auth_url = app.get_authorization_request_url(
                    SCOPE,
                    redirect_uri=REDIRECT_URI
                )
                st.markdown(f"[Microsoft ile Giriş Yap]({auth_url})")

                # Callback: URL'de kod varsa token al
                query_params = st.query_params
                if "code" in query_params:
                    code = query_params["code"]
                    result = app.acquire_token_by_authorization_code(
                        code,
                        scopes=SCOPE,
                        redirect_uri=REDIRECT_URI
                    )
                    if "access_token" in result:
                        user = requests.get(
                            "https://graph.microsoft.com/v1.0/me",
                            headers={"Authorization": f"Bearer {result['access_token']}"}
                        ).json()
                        st.session_state.authenticated = True
                        st.session_state.current_user = user.get("userPrincipalName", user.get("mail", ""))
                        st.session_state.user_role = "azure_user"
                        st.session_state.current_page = "dashboard"
                        st.session_state.token = result
                        st.success("✅ Azure AD girişi başarılı!")
                        st.rerun()
                    else:
                        st.error("Giriş başarısız: " + str(result.get("error_description", "Bilinmeyen hata")))
            except Exception as e:
                st.error(f"❌ Azure AD authentication hatası: {str(e)}")

def show_dashboard():
    """Display the main dashboard with agent selection"""
    
    # Force session state agents to be a dictionary if it's not
    if "agents" in st.session_state and not isinstance(st.session_state.agents, dict):
        st.warning(f"⚠️ Resetting invalid agents data from session state (was {type(st.session_state.agents)})")
        st.session_state.agents = {}
    
    # Header with logout
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        st.markdown('<h1 class="main-header">🤖 Azure AI Agents Dashboard</h1>', 
                    unsafe_allow_html=True)
    with col2:
        if st.session_state.user_role == "admin":
            if st.button("⚙️ Settings"):
                st.session_state.current_page = "settings"
                st.rerun()
    with col3:
        if st.button("🚪 Logout"):
            # Reset session state
            for key in list(st.session_state.keys()):
                if key not in ['agents', 'user_manager']:
                    del st.session_state[key]
            st.session_state.current_page = "login"
            st.rerun()
    
    # User info
    st.info(f"👋 Welcome {st.session_state.current_user} ({st.session_state.user_role})")
    
    # Agent grid
    st.subheader("🤖 Available AI Agents")
    
    # Get latest agents from blob storage
    try:
        from azure_utils import AzureConfig, BlobStorageAgentManager
        # Initialize without any extra parameters
        blob_agent_manager = BlobStorageAgentManager(AzureConfig())
        agents = blob_agent_manager.get_active_agents()  # Only show active agents
        
        # If no agents from blob storage, try backup configuration
        if not agents:
            backup_path = "config_backup/agent_configs.json"
            if os.path.exists(backup_path):
                import json
                with open(backup_path, 'r', encoding='utf-8') as f:
                    all_agents = json.load(f)
                # Filter only enabled agents and ensure all required fields
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
                st.info(f"📂 Loaded {len(agents)} agents from backup configuration")
        
        # Update session state with fresh data
        st.session_state.agents = agents
    except Exception as e:
        st.error(f"Error loading agents from blob storage: {e}")
        agents = st.session_state.get("agents", {})
        
        # Try backup configuration as final fallback
        if not agents:
            backup_path = "config_backup/agent_configs.json"
            if os.path.exists(backup_path):
                try:
                    import json
                    with open(backup_path, 'r', encoding='utf-8') as f:
                        all_agents = json.load(f)
                    # Filter only enabled agents and ensure all required fields
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
                    st.session_state.agents = agents
                    st.info(f"📂 Fallback: Loaded {len(agents)} agents from backup configuration")
                except Exception as backup_error:
                    st.error(f"Error loading backup configuration: {backup_error}")
                    agents = {}
    
    # Safety check: ensure agents is always a dictionary
    if not isinstance(agents, dict):
        st.error(f"Invalid agents data format. Expected dict, got {type(agents)}. Resetting to empty dictionary.")
        st.error(f"Agent data content: {agents}")
        agents = {}
        st.session_state.agents = agents
    
    cols = st.columns(3)
    
    for idx, (agent_id, agent_config) in enumerate(agents.items()):
        col = cols[idx % 3]
        
        with col:
            # Check permissions
            has_access = (st.session_state.user_role == "admin" or 
                         st.session_state.user_manager.has_permission(
                             st.session_state.current_user, agent_id, "access"))
            

            
            # Agent card
            card_style = "agent-card" if has_access else "agent-card" + " opacity: 0.5;"
            
            st.markdown(f"""
            <div class="{card_style}" style="border-color: {agent_config['color']};">
                <div class="agent-icon">{agent_config['icon']}</div>
                <div class="agent-title">{agent_config['name']}</div>
                <div class="agent-description">{agent_config['description']}</div>
                <div class="agent-stats">
                    <small>
                        📁 Container: {agent_config['container_name']}<br>
                         Categories: {', '.join(agent_config['categories'])}
                    </small>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            if has_access:
                if st.button(f"Open {agent_config['name']}", key=f"open_{agent_id}", type="primary"):
                    st.session_state.selected_agent = agent_id
                    st.session_state.current_page = "agent_interface"
                    st.rerun()
            else:
                st.warning("⚠️ No access permission")
    
    # System status
    st.markdown("---")
    st.subheader("📊 System Status")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Agents", len(agents))
    with col2:
        accessible_agents = sum(1 for agent_id in agents.keys() 
                              if st.session_state.user_role == "admin" or 
                              st.session_state.user_manager.has_permission(
                                  st.session_state.current_user, agent_id, "access"))
        st.metric("Accessible Agents", accessible_agents)
    with col3:
        st.metric("Active Sessions", len(st.session_state.get("thread_ids", {})))
    with col4:
        st.metric("Connected Clients", len(st.session_state.get("ai_clients", {})))

def show_agent_interface():
    """Display the agent interface with chat and document management"""
    
    if not st.session_state.selected_agent:
        st.error("No agent selected")
        return
    
    agent_config = st.session_state.agents[st.session_state.selected_agent]
    
    # Header
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown(f"""
        <h1 class="main-header">
            {agent_config['icon']} {agent_config['name']}
        </h1>
        """, unsafe_allow_html=True)
    with col2:
        if st.button("🏠 Back to Dashboard"):
            st.session_state.current_page = "dashboard"
            st.rerun()
    
    st.markdown(f"**Description:** {agent_config['description']}")
    
    # Tab navigation
    tab1, tab2, tab3 = st.tabs(["💬 Chat", "📁 Documents", "⚙️ Settings"])
    
    with tab1:
        show_agent_chat(agent_config)
    
    with tab2:
        show_document_management(agent_config)
    
    with tab3:
        show_agent_settings(agent_config)

def show_agent_chat(agent_config: Dict):
    """Display the chat interface for the selected agent"""
    
    agent_id = agent_config['id']
    
    # Initialize agent client if needed
    if agent_id not in st.session_state.ai_clients:
        try:
            with st.spinner("🔄 Connecting to agent..."):
                from azure_utils import EnhancedAzureAIAgentClient, AzureConfig
                
                config = AzureConfig()
                client = EnhancedAzureAIAgentClient(
                    agent_config['connection_string'],
                    agent_config['agent_id'],
                    config
                )
                
                thread = client.create_thread()
                
                st.session_state.ai_clients[agent_id] = client
                st.session_state.thread_ids[agent_id] = thread.id
                st.session_state.connection_status[agent_id] = True
                
                if agent_id not in st.session_state.messages:
                    st.session_state.messages[agent_id] = []
                
            st.success("✅ Connected to agent!")
            
        except Exception as e:
            st.error(f"❌ Connection failed: {str(e)}")
            st.session_state.connection_status[agent_id] = False
            return
    
    # Check permissions
    can_chat = (st.session_state.user_role == "admin" or 
                st.session_state.user_manager.has_permission(
                    st.session_state.current_user, agent_id, "chat"))
    
    if not can_chat:
        st.warning("⚠️ You don't have chat permission for this agent")
        return
    
    # Display chat messages
    chat_container = st.container()
    with chat_container:
        agent_messages = st.session_state.messages.get(agent_id, [])
        
        for message in agent_messages:
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
                    <strong>{agent_config['icon']} {agent_config['name']}:</strong><br>
                    {message["content"]}
                </div>
                """, unsafe_allow_html=True)
    
    # Chat input
    user_input = st.chat_input(f"Ask {agent_config['name']}...", key=f"chat_{agent_id}")
    
    if user_input and st.session_state.connection_status.get(agent_id, False):
        # Add user message
        if agent_id not in st.session_state.messages:
            st.session_state.messages[agent_id] = []
        
        st.session_state.messages[agent_id].append({"role": "user", "content": user_input})
        
        # Get AI response
        try:
            with st.spinner(f"🤔 {agent_config['name']} is thinking..."):
                client = st.session_state.ai_clients[agent_id]
                thread_id = st.session_state.thread_ids[agent_id]
                
                response = client.send_message_and_get_response(thread_id, user_input)
            
            # Add assistant response
            st.session_state.messages[agent_id].append({"role": "assistant", "content": response})
            
        except Exception as e:
            error_msg = f"Error getting response: {str(e)}"
            st.error(error_msg)
            st.session_state.messages[agent_id].append({"role": "assistant", "content": error_msg})
        
        st.rerun()
    
    # Chat controls
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 New Conversation", key=f"new_conv_{agent_id}"):
            st.session_state.messages[agent_id] = []
            # Create new thread
            if agent_id in st.session_state.ai_clients:
                client = st.session_state.ai_clients[agent_id]
                thread = client.create_thread()
                st.session_state.thread_ids[agent_id] = thread.id
            st.rerun()
    
    with col2:
        if st.button("💾 Export Chat", key=f"export_{agent_id}"):
            if agent_id in st.session_state.messages:
                chat_export = ""
                for msg in st.session_state.messages[agent_id]:
                    role = "You" if msg["role"] == "user" else agent_config['name']
                    chat_export += f"{role}: {msg['content']}\n\n"
                
                st.download_button(
                    label="📥 Download Chat",
                    data=chat_export,
                    file_name=f"{agent_config['name']}_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

def show_document_management(agent_config: Dict):
    """Display document management interface"""
    
    agent_id = agent_config['id']
    
    # Check permissions
    can_upload = (st.session_state.user_role == "admin" or 
                  st.session_state.user_manager.has_permission(
                      st.session_state.current_user, agent_id, "document_upload"))
    
    can_delete = (st.session_state.user_role == "admin" or 
                  st.session_state.user_manager.has_permission(
                      st.session_state.current_user, agent_id, "document_delete"))
    

    
    # Document upload section
    if can_upload:
        st.subheader("📤 Upload Documents")
        
        uploaded_files = st.file_uploader(
            "Choose files to upload",
            type=['pdf', 'docx', 'txt'],
            accept_multiple_files=True,
            key=f"upload_{agent_id}"
        )
        
        if uploaded_files:
            if st.button("🚀 Upload Files", key=f"upload_btn_{agent_id}"):
                try:
                    # Initialize client if needed
                    if agent_id not in st.session_state.ai_clients:
                        from azure_utils import EnhancedAzureAIAgentClient, AzureConfig
                        config = AzureConfig()
                        client = EnhancedAzureAIAgentClient(
                            agent_config['connection_string'],
                            agent_config['agent_id'],
                            config
                        )
                        st.session_state.ai_clients[agent_id] = client
                    
                    client = st.session_state.ai_clients[agent_id]
                    container_name = agent_config['container_name']
                    
                    success_count = 0
                    error_details = []
                    success_details = []
                    
                    with st.spinner("Uploading documents to blob storage..."):
                        for uploaded_file in uploaded_files:
                            try:
                                file_content = uploaded_file.read()
                                
                                # Get index name from agent config
                                index_name = agent_config.get('search_index')
                                
                                # Upload document with indexing
                                result = client.upload_and_index_document(
                                    container_name,
                                    uploaded_file.name,
                                    file_content,
                                    uploaded_file.type or "application/octet-stream",
                                    index_name
                                )
                                
                                if result['success']:
                                    success_count += 1
                                    success_details.append(f"📁 {uploaded_file.name}: ✅ Uploaded to blob storage")
                                    # Show indexing status
                                    if result.get('indexed'):
                                        success_details.append(f"🔍 {uploaded_file.name}: ✅ Indexing triggered")
                                    elif index_name:
                                        success_details.append(f"🔍 {uploaded_file.name}: ⚠️ Indexing failed - {result.get('index_message', 'Unknown error')}")
                                else:
                                    error_details.append(f"❌ {uploaded_file.name}: {result.get('message', 'Upload failed')}")
                                    
                            except Exception as file_error:
                                error_details.append(f"💥 {uploaded_file.name}: {str(file_error)}")
                    
                    # Show detailed results with indexing status
                    if success_count == len(uploaded_files):
                        st.success(f"✅ Successfully uploaded {success_count}/{len(uploaded_files)} files to blob storage!")
                        # Check if any files had indexing
                        any_indexed = any('✅ Indexing triggered' in detail for detail in success_details)
                        if any_indexed:
                            st.info("🔍 Indexing has been triggered for search functionality")
                        if success_details:
                            with st.expander("📋 Upload Details"):
                                for detail in success_details:
                                    st.write(detail)
                    else:
                        st.error(f"❌ Only {success_count}/{len(uploaded_files)} files uploaded successfully")
                        if error_details:
                            with st.expander("📋 Error Details"):
                                for detail in error_details:
                                    st.write(detail)
                    
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"❌ Upload operation failed: {str(e)}")
                    st.info("💡 If you're seeing a 400 error, this might be due to:")
                    st.write("• File size too large (limit: 200MB per file)")
                    st.write("• Unsupported file format")
                    st.write("• Azure service configuration issues")
                    st.write("• Network connectivity problems")
                    
                    with st.expander("🔧 Troubleshooting"):
                        st.write("1. Check if the file is a supported format (PDF, DOCX, TXT)")
                        st.write("2. Ensure file size is under 200MB")
                        st.write("3. Try uploading one file at a time")
                        st.write("4. Contact administrator if the problem persists")
    else:
        st.warning("⚠️ You don't have document upload permission for this agent")
    

    
    st.markdown("---")
    
    # Document list section
    st.subheader("📁 Document Library")
    
    try:
        # Initialize client if needed
        if agent_id not in st.session_state.ai_clients:
            from azure_utils import EnhancedAzureAIAgentClient, AzureConfig
            config = AzureConfig()
            client = EnhancedAzureAIAgentClient(
                agent_config['connection_string'],
                agent_config['agent_id'],
                config
            )
            st.session_state.ai_clients[agent_id] = client
        
        client = st.session_state.ai_clients[agent_id]
        container_name = agent_config['container_name']
        
        documents = client.list_documents(container_name)
        
        if documents:
            # Add size_mb to each document
            for doc in documents:
                doc['size_mb'] = (doc['size'] / 1024 / 1024) if doc['size'] else 0
            
            # Create DataFrame for better display
            df_docs = pd.DataFrame(documents)
            df_docs['last_modified'] = pd.to_datetime(df_docs['last_modified']).dt.strftime('%Y-%m-%d %H:%M')
            
            # Display documents
            for idx, doc in enumerate(documents):
                with st.expander(f"📄 {doc['name']} ({doc['size_mb']:.2f} MB)"):
                    col1, col2, col3 = st.columns([2, 1, 1])
                    with col1:
                        st.write(f"**Size:** {doc['size_mb']:.2f} MB")
                        st.write(f"**Modified:** {doc['last_modified']}")
                        st.write(f"**Type:** {doc['content_type']}")
                    
                    with col2:
                        if st.button("📥 Download", key=f"download_{agent_id}_{idx}"):
                            st.info("Download functionality coming soon!")
                    
                    with col3:
                        if can_delete:
                            if st.button("🗑️ Delete", key=f"delete_{agent_id}_{idx}", type="secondary"):
                                # Get index name from agent config - strict mode, no fallback
                                index_name = agent_config.get('search_index')
                                if not index_name:
                                    st.error(f"❌ No search index configured for agent '{agent_id}'. Please configure 'search_index' in agent settings.")
                                else:
                                    if client.delete_document(container_name, doc['name'], index_name):
                                        st.success(f"✅ Deleted {doc['name']}")
                                        st.info("🔄 Reindexing triggered automatically")
                                        st.rerun()
                                    else:
                                        st.error(f"❌ Failed to delete {doc['name']} from index '{index_name}'")
                        else:
                            st.write("🔒 No delete permission")
        else:
            st.info("📭 No documents found in this agent's library")
    
    except Exception as e:
        st.error(f"❌ Error loading documents: {str(e)}")

def show_agent_settings(agent_config: Dict):
    """Display agent settings and configuration"""
    
    st.subheader("⚙️ Agent Configuration")
    
    # Display current settings
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Connection Details:**")
        st.code(f"Agent ID: {agent_config['agent_id']}")
        st.code(f"Container: {agent_config['container_name']}")
    
    with col2:
        st.markdown("**Agent Properties:**")
        st.write(f"**Name:** {agent_config['name']}")
        st.write(f"**Icon:** {agent_config['icon']}")
        st.write(f"**Color:** {agent_config['color']}")
        st.write(f"**Categories:** {', '.join(agent_config['categories'])}")
    
    # Connection status
    agent_id = agent_config['id']
    if agent_id in st.session_state.connection_status:
        status = st.session_state.connection_status[agent_id]
        if status:
            st.success("🟢 Agent Connected")
        else:
            st.error("🔴 Agent Disconnected")
    else:
        st.info("⚪ Connection Not Tested")
    
    # Test connection button
    if st.button("🔌 Test Connection", key=f"test_{agent_id}"):
        try:
            from azure_utils import EnhancedAzureAIAgentClient, AzureConfig
            config = AzureConfig()
            client = EnhancedAzureAIAgentClient(
                agent_config['connection_string'],
                agent_config['agent_id'],
                config
            )
            st.success("✅ Connection test successful!")
            st.session_state.connection_status[agent_id] = True
        except Exception as e:
            st.error(f"❌ Connection test failed: {str(e)}")
            st.session_state.connection_status[agent_id] = False

def show_settings():
    """Display comprehensive settings interface for admin users with blob storage integration"""
    
    if st.session_state.user_role != "admin":
        st.error("⚠️ Admin access required")
        return
    
    # Header
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown('<h1 class="main-header">⚙️ Settings (Blob Storage)</h1>', unsafe_allow_html=True)
    with col2:
        if st.button("🏠 Back to Dashboard"):
            st.session_state.current_page = "dashboard"
            st.rerun()
    
    # Settings tabs
    tab1, tab2, tab3 = st.tabs(["👥 User Management", "🤖 Agent Configuration", "🔧 System Settings"])
    
    with tab1:
        show_blob_user_management_tab()
    
    with tab2:
        show_blob_agent_configuration_tab()
    
    with tab3:
        show_system_settings_tab()

def show_blob_user_management_tab():
    """Enhanced user management tab with blob storage integration"""
    st.subheader("📋 User Management (Blob Storage)")
    
    # Get current users from blob storage
    try:
        users = st.session_state.user_manager.get_all_users()
        
        # Ensure users is a dictionary
        if not isinstance(users, dict):
            st.error(f"❌ Invalid user data format. Expected dictionary, got {type(users)}")
            users = {}
    except Exception as e:
        st.error(f"❌ Error loading users: {e}")
        users = {}
    
    # Get agents from blob storage as well
    from azure_utils import AzureConfig, BlobStorageAgentManager
    try:
        # Initialize without any extra parameters
        blob_agent_manager = BlobStorageAgentManager(AzureConfig())
        agents = blob_agent_manager.get_all_agents()
    except Exception as e:
        st.error(f"Error loading agents from blob storage: {e}")
        agents = {}
    
    # Add new user section
    with st.expander("➕ Add New User"):
        with st.form("add_user_form_settings"):
            new_username = st.text_input("Username", placeholder="Enter username")
            new_role = st.selectbox("Role", ["standard", "admin"])
            
            st.write("**Agent Permissions:**")
            new_permissions = {}
            
            for agent_id, agent_config in agents.items():
                st.write(f"**{agent_config['name']} ({agent_id})**")
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    access = st.checkbox(f"Access", key=f"blob_new_access_{agent_id}")
                with col2:
                    chat = st.checkbox(f"Chat", key=f"blob_new_chat_{agent_id}")
                with col3:
                    upload = st.checkbox(f"Upload", key=f"blob_new_upload_{agent_id}")
                with col4:
                    delete = st.checkbox(f"Delete", key=f"blob_new_delete_{agent_id}")
                
                new_permissions[agent_id] = {
                    'access': access,
                    'chat': chat,
                    'document_upload': upload,
                    'document_delete': delete
                }
            
            if st.form_submit_button("➕ Add User", type="primary"):
                if new_username and new_username not in users:
                    if st.session_state.user_manager.add_user(new_username, new_role, new_permissions):
                        st.success(f"✅ User '{new_username}' added successfully and saved to blob storage!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to add user to blob storage")
                elif new_username in users:
                    st.error("❌ Username already exists")
                else:
                    st.error("❌ Please enter a username")
    
    # Display current users
    st.markdown("---")
    
    if users:
        for username, user_data in users.items():
            # Ensure user_data is a dictionary
            if not isinstance(user_data, dict):
                st.error(f"❌ Invalid user data for {username}: {type(user_data)}")
                continue
                
            with st.expander(f"👤 {username} ({user_data.get('role', 'Unknown')}) - Created: {user_data.get('created_at', 'Unknown')[:10]}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Role:** {user_data.get('role', 'Unknown')}")
                    st.write(f"**Created:** {user_data.get('created_at', 'Unknown')}")
                    if user_data.get('updated_at'):
                        st.write(f"**Last Updated:** {user_data.get('updated_at')}")
            
            with col2:
                # Blob storage operations
                if st.button(f"🔄 Refresh", key=f"refresh_{username}"):
                    # Force reload from blob storage
                    st.session_state.user_manager = st.session_state.user_manager.__class__()
                    st.rerun()
            
            if user_data.get('role') != 'admin':
                st.write("**Agent Permissions:**")
                
                # Permission matrix
                permission_data = []
                for agent_id, agent_config in agents.items():
                    user_perms = user_data.get('permissions', {}).get(agent_id, {})
                    permission_data.append({
                        'Agent': agent_config['name'],
                        'Agent ID': agent_id,
                        'Access': '✅' if user_perms.get('access', False) else '❌',
                        'Chat': '✅' if user_perms.get('chat', False) else '❌',
                        'Upload': '✅' if user_perms.get('document_upload', False) else '❌',
                        'Delete': '✅' if user_perms.get('document_delete', False) else '❌'
                    })
                
                if permission_data:
                    df_perms = pd.DataFrame(permission_data)
                    st.dataframe(df_perms, use_container_width=True)
                else:
                    st.info("No specific permissions set")
                
                # Edit permissions button
                if st.button(f"✏️ Edit Permissions", key=f"edit_{username}"):
                    st.session_state[f"editing_{username}"] = True
                    st.rerun()
                
                # Edit permissions form
                if st.session_state.get(f"editing_{username}", False):
                    st.write("**Edit Permissions (Will save to blob storage):**")
                    with st.form(f"edit_perms_{username}"):
                        updated_permissions = {}
                        
                        for agent_id, agent_config in agents.items():
                            st.write(f"**{agent_config['name']} ({agent_id})**")
                            col1, col2, col3, col4 = st.columns(4)
                            
                            current_perms = user_data.get('permissions', {}).get(agent_id, {})
                            
                            with col1:
                                access = st.checkbox("Access", 
                                                   value=current_perms.get('access', False),
                                                   key=f"edit_access_{username}_{agent_id}")
                            with col2:
                                chat = st.checkbox("Chat", 
                                                 value=current_perms.get('chat', False),
                                                 key=f"edit_chat_{username}_{agent_id}")
                            with col3:
                                upload = st.checkbox("Upload", 
                                                    value=current_perms.get('document_upload', False),
                                                    key=f"edit_upload_{username}_{agent_id}")
                            with col4:
                                delete = st.checkbox("Delete", 
                                                    value=current_perms.get('document_delete', False),
                                                    key=f"edit_delete_{username}_{agent_id}")
                            
                            updated_permissions[agent_id] = {
                                'access': access,
                                'chat': chat,
                                'document_upload': upload,
                                'document_delete': delete
                            }
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.form_submit_button("💾 Save to Blob Storage", type="primary"):
                                if st.session_state.user_manager.update_user_permissions(username, updated_permissions):
                                    st.session_state[f"editing_{username}"] = False
                                    st.success("✅ Permissions updated and saved to blob storage!")
                                    st.rerun()
                                else:
                                    st.error("❌ Failed to save permissions to blob storage")
                        with col2:
                            if st.form_submit_button("❌ Cancel"):
                                st.session_state[f"editing_{username}"] = False
                                st.rerun()
            else:
                st.success("👑 Full admin access to all agents and features")
            
            # Delete user button (except for admin)
            if username != "admin":
                if st.button(f"🗑️ Delete User (from Blob)", key=f"delete_{username}", type="secondary"):
                    if st.session_state.user_manager.delete_user(username):
                        st.success(f"🗑️ User {username} deleted from blob storage!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to delete user from blob storage")

def show_blob_agent_configuration_tab():
    """Enhanced agent configuration tab with blob storage integration"""
    st.subheader("🤖 Agent Configuration (Blob Storage)")
    
    # Get current agents from blob storage using AgentManager
    from azure_utils import AzureConfig, BlobStorageAgentManager
    try:
        # Initialize without any extra parameters
        blob_agent_manager = BlobStorageAgentManager(AzureConfig())
        agents = blob_agent_manager.get_all_agents()
        
        # If no agents from blob storage, try backup configuration as fallback
        if not agents:
            backup_path = "config_backup/agent_configs.json"
            if os.path.exists(backup_path):
                import json
                with open(backup_path, 'r', encoding='utf-8') as f:
                    all_agents = json.load(f)
                # Convert backup format to expected format with all required fields
                agents = {}
                for agent_id, config in all_agents.items():
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
                        'enabled': config.get('enabled', True),
                        'status': 'active' if config.get('enabled', True) else 'inactive',
                        'created_at': config.get('created_at', '2025-01-01T00:00:00Z')
                    }
                st.info(f"📂 Loaded {len(agents)} agents from backup configuration (blob storage not available)")
        
    except Exception as e:
        st.error(f"Error loading agents from blob storage: {e}")
        # Try backup configuration as final fallback
        agents = {}
        backup_path = "config_backup/agent_configs.json"
        if os.path.exists(backup_path):
            try:
                import json
                with open(backup_path, 'r', encoding='utf-8') as f:
                    all_agents = json.load(f)
                # Convert backup format to expected format with all required fields
                agents = {}
                for agent_id, config in all_agents.items():
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
                        'enabled': config.get('enabled', True),
                        'status': 'active' if config.get('enabled', True) else 'inactive',
                        'created_at': config.get('created_at', '2025-01-01T00:00:00Z')
                    }
                st.warning(f"⚠️ Fallback: Loaded {len(agents)} agents from backup configuration due to blob storage error")
            except Exception as backup_error:
                st.error(f"Error loading backup configuration: {backup_error}")
                agents = {}
    
    # Add new agent section
    with st.expander("➕ Add New Agent"):
        with st.form("add_agent_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_agent_id = st.text_input("Agent ID", placeholder="e.g., hr_agent")
                new_agent_name = st.text_input("Agent Name", placeholder="e.g., HR Assistant")
                
                # Icon selector - use radio for better form experience
                new_agent_icon = show_icon_selector(default_icon="🤖", key="add_agent", use_radio=True)
                
                new_agent_color = st.color_picker("Agent Color", "#FF6B6B")
            
            with col2:
                new_agent_description = st.text_area("Description", placeholder="Agent description")
                new_connection_string = st.text_input("Connection String", placeholder="Azure AI connection string")
                new_agent_ai_id = st.text_input("AI Agent ID", placeholder="Assistant ID")
                new_container_name = st.text_input("Container Name", placeholder="document-container")
                new_search_index = st.text_input("Search Index", placeholder="search-index-name", 
                                                help="Index name for search functionality")
            
            new_categories = st.text_input("Categories (comma-separated)", placeholder="category1, category2")
            
            if st.form_submit_button("➕ Add Agent", type="primary"):
                if new_agent_id and new_agent_name:
                    agent_config = {
                        "id": new_agent_id,
                        "name": new_agent_name,
                        "icon": new_agent_icon or "🤖",
                        "description": new_agent_description,
                        "connection_string": new_connection_string,
                        "agent_id": new_agent_ai_id,
                        "container_name": new_container_name,
                        "search_index": new_search_index,
                        "color": new_agent_color,
                        "categories": [cat.strip() for cat in new_categories.split(",") if cat.strip()]
                    }
                    
                    if blob_agent_manager.add_agent(agent_config):
                        st.success(f"✅ Agent '{new_agent_name}' added successfully and saved to blob storage!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to add agent to blob storage")
                else:
                    st.error("❌ Please enter Agent ID and Name")
    
    # Display current agents
    st.markdown("---")
    
    for agent_id, agent_config in agents.items():
        status = agent_config.get('status', 'active')
        status_icon = "🟢" if status == 'active' else "🔴"
        
        with st.expander(f"{status_icon} {agent_config.get('icon', '🤖')} {agent_config.get('name', agent_id)} - Created: {agent_config.get('created_at', 'Unknown')[:10]}"):
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                st.write(f"**ID:** {agent_id}")
                st.write(f"**Name:** {agent_config.get('name', 'N/A')}")
                st.write(f"**Description:** {agent_config.get('description', 'N/A')}")
                st.write(f"**Status:** {status}")
            
            with col2:
                st.write(f"**Container:** {agent_config.get('container_name', 'N/A')}")
                st.write(f"**AI Agent ID:** {agent_config.get('agent_id', 'N/A')}")
                st.write(f"**Categories:** {', '.join(agent_config.get('categories', []))}")
            
            with col3:
                # Status toggle
                new_status = "inactive" if status == "active" else "active"
                if st.button(f"{'⏸️' if status == 'active' else '▶️'} {new_status.title()}", key=f"toggle_{agent_id}"):
                    if blob_agent_manager.set_agent_status(agent_id, new_status):
                        st.success(f"✅ Agent status updated to {new_status}")
                        st.rerun()
                    else:
                        st.error("❌ Failed to update agent status")
                
                # Delete agent
                if st.button(f"🗑️ Delete", key=f"delete_agent_{agent_id}", type="secondary"):
                    if blob_agent_manager.delete_agent(agent_id):
                        st.success(f"🗑️ Agent {agent_id} deleted from blob storage!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to delete agent from blob storage")
            
            # Edit agent form
            if st.button(f"✏️ Edit Agent", key=f"edit_agent_{agent_id}"):
                st.session_state[f"editing_agent_{agent_id}"] = True
                st.rerun()
            
            if st.session_state.get(f"editing_agent_{agent_id}", False):
                st.write("**Edit Agent Configuration (Will save to blob storage):**")
                with st.form(f"edit_agent_{agent_id}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        edit_name = st.text_input("Name", value=agent_config.get('name', ''))
                        
                        # Icon selector for editing
                        current_icon = agent_config.get('icon', '🤖')
                        edit_icon = show_icon_selector(default_icon=current_icon, key=f"edit_agent_{agent_id}")
                        
                        # Extract valid hex color from gradient or use default
                        color_value = agent_config.get('color', '#FF6B6B')
                        if color_value and '#' in color_value:
                            # Extract first hex color from gradient
                            import re
                            hex_match = re.search(r'#[0-9a-fA-F]{6}', color_value)
                            if hex_match:
                                color_value = hex_match.group()
                            else:
                                color_value = '#FF6B6B'
                        else:
                            color_value = '#FF6B6B'
                        edit_color = st.color_picker("Color", value=color_value)
                    
                    with col2:
                        edit_description = st.text_area("Description", value=agent_config.get('description', ''))
                        edit_connection_string = st.text_input("Connection String", 
                                                             value=agent_config.get('connection_string', ''),
                                                             placeholder="Azure AI connection string")
                        edit_agent_ai_id = st.text_input("AI Agent ID", 
                                                        value=agent_config.get('agent_id', ''),
                                                        placeholder="Assistant ID")
                        edit_container = st.text_input("Container Name", value=agent_config.get('container_name', ''))
                        edit_search_index = st.text_input("Search Index", value=agent_config.get('search_index', ''), 
                                                        help="Index name for search functionality")
                    
                    edit_categories = st.text_input("Categories (comma-separated)", 
                                                  value=', '.join(agent_config.get('categories', [])))
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.form_submit_button("💾 Save to Blob Storage", type="primary"):
                            updated_config = agent_config.copy()
                            updated_config.update({
                                "name": edit_name,
                                "icon": edit_icon,
                                "description": edit_description,
                                "connection_string": edit_connection_string,
                                "agent_id": edit_agent_ai_id,
                                "container_name": edit_container,
                                "search_index": edit_search_index,
                                "color": edit_color,
                                "categories": [cat.strip() for cat in edit_categories.split(",") if cat.strip()]
                            })
                            
                            if blob_agent_manager.update_agent(agent_id, updated_config):
                                st.session_state[f"editing_agent_{agent_id}"] = False
                                st.success("✅ Agent configuration updated and saved to blob storage!")
                                st.rerun()
                            else:
                                st.error("❌ Failed to save agent configuration to blob storage")
                    with col2:
                        if st.form_submit_button("❌ Cancel"):
                            st.session_state[f"editing_agent_{agent_id}"] = False
                            st.rerun()
    
def show_agent_configuration_tab():
    """Agent configuration tab content"""
    st.subheader("🤖 Agent Configuration")
    
    agents = st.session_state.agents
    
    # Current agents
    st.write("### 📋 Current Agents")
    for agent_id, agent_config in agents.items():
        with st.expander(f"🤖 {agent_config['name']} ({agent_id})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Basic Information:**")
                st.write(f"- **Name:** {agent_config['name']}")
                st.write(f"- **Description:** {agent_config['description']}")
                st.write(f"- **Icon:** {agent_config['icon']}")
                st.write(f"- **Color:** {agent_config['color']}")
                
            with col2:
                st.write("**Azure Configuration:**")
                st.write(f"- **Container:** {agent_config['container_name']}")
                st.write(f"- **Connection String:** {agent_config['connection_string'][:30]}...")
                st.write(f"- **Agent ID:** {agent_config['agent_id']}")
            
            # Edit agent button
            if st.button(f"✏️ Edit Agent", key=f"edit_agent_{agent_id}"):
                st.session_state[f"editing_agent_{agent_id}"] = True
                st.rerun()
            
            # Edit agent form
            if st.session_state.get(f"editing_agent_{agent_id}", False):
                with st.form(f"edit_agent_form_{agent_id}"):
                    st.write("**Edit Agent Configuration:**")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        new_name = st.text_input("Name", value=agent_config['name'], key=f"edit_name_{agent_id}")
                        new_description = st.text_area("Description", value=agent_config['description'], key=f"edit_desc_{agent_id}")
                        
                        # Icon selector for editing (second form) - use radio for better form experience
                        current_icon = agent_config.get('icon', '🤖')
                        new_icon = show_icon_selector(default_icon=current_icon, key=f"edit_agent_form_{agent_id}", use_radio=True)
                        
                        # Extract valid hex color from gradient or use default
                        color_value = agent_config.get('color', '#FF6B6B')
                        if color_value and '#' in color_value:
                            # Extract first hex color from gradient
                            import re
                            hex_match = re.search(r'#[0-9a-fA-F]{6}', color_value)
                            if hex_match:
                                color_value = hex_match.group()
                            else:
                                color_value = '#FF6B6B'
                        else:
                            color_value = '#FF6B6B'
                        new_color = st.color_picker("Color", value=color_value, key=f"edit_color_{agent_id}")
                    
                    with col2:
                        new_container = st.text_input("Container Name", value=agent_config['container_name'], key=f"edit_container_{agent_id}")
                        new_connection_string = st.text_input("Azure Connection String", value=agent_config['connection_string'], type="password", key=f"edit_conn_{agent_id}")
                        new_agent_id = st.text_input("Agent ID", value=agent_config['agent_id'], key=f"edit_agent_id_{agent_id}")
                        new_search_index = st.text_input("Search Index", value=agent_config.get('search_index', ''), 
                                                        key=f"edit_search_{agent_id}", 
                                                        help="Index name for search functionality")
                    
                    new_categories = st.text_input("Categories (comma-separated)", 
                                                  value=', '.join(agent_config.get('categories', [])),
                                                  key=f"edit_categories_{agent_id}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.form_submit_button("💾 Save Changes", type="primary"):
                            # Update agent configuration
                            st.session_state.agents[agent_id].update({
                                "name": new_name,
                                "description": new_description,
                                "icon": new_icon,
                                "color": new_color,
                                "container_name": new_container,
                                "search_index": new_search_index,
                                "connection_string": new_connection_string,
                                "agent_id": new_agent_id,
                                "categories": [cat.strip() for cat in new_categories.split(",") if cat.strip()]
                            })
                            st.session_state[f"editing_agent_{agent_id}"] = False
                            st.success("✅ Agent configuration updated!")
                            st.rerun()
                    with col2:
                        if st.form_submit_button("❌ Cancel"):
                            st.session_state[f"editing_agent_{agent_id}"] = False
                            st.rerun()
            
            # Delete agent button
            if st.button(f"🗑️ Delete Agent", key=f"delete_agent_{agent_id}", type="secondary"):
                if st.session_state.get(f"confirm_delete_{agent_id}", False):
                    del st.session_state.agents[agent_id]
                    st.success(f"🗑️ Agent {agent_config['name']} deleted!")
                    st.rerun()
                else:
                    st.session_state[f"confirm_delete_{agent_id}"] = True
                    st.warning("⚠️ Click again to confirm deletion")
    
    # Add new agent section
    st.markdown("---")
    st.subheader("➕ Add New Agent")
    
    with st.form("add_agent"):
        col1, col2 = st.columns(2)
        
        with col1:
            agent_name = st.text_input("Agent Name")
            agent_description = st.text_area("Description")
            
            # Icon selector for third form - use radio for better form experience
            agent_icon = show_icon_selector(default_icon="🤖", key="add_agent_third", use_radio=True)
            
            agent_color = st.color_picker("Color", value="#0078d4")
        
        with col2:
            container_name = st.text_input("Container Name")
            connection_string = st.text_input("Azure Connection String", type="password")
            agent_id = st.text_input("Agent ID")
        
        categories = st.text_input("Categories (comma-separated)", placeholder="e.g., documents, reports, policies")
        
        if st.form_submit_button("Add Agent", type="primary"):
            if agent_name and container_name and connection_string and agent_id:
                new_agent_id = agent_name.lower().replace(" ", "_")
                
                if new_agent_id not in agents:
                    st.session_state.agents[new_agent_id] = {
                        "name": agent_name,
                        "description": agent_description,
                        "icon": agent_icon,
                        "color": agent_color,
                        "container_name": container_name,
                        "search_index": "",  # Empty since search is disabled
                        "azure_connection_string": connection_string,
                        "agent_id": agent_id,
                        "categories": [cat.strip() for cat in categories.split(",") if cat.strip()]
                    }
                    st.success(f"✅ Agent {agent_name} added successfully!")
                    st.rerun()
                else:
                    st.error("❌ Agent with this name already exists")
            else:
                st.error("❌ Please fill in all required fields")

def show_system_settings_tab():
    """System settings tab content"""
    st.subheader("🔧 System Settings")
    
    # User Management (only for admins)
    if st.session_state.user_role == "admin":
        st.write("### 👥 User Management")
        
        # User list
        users = st.session_state.user_manager.get_all_users()
        
        if users:
            st.write("**Current Users:**")
            user_df = pd.DataFrame([
                {
                    "Username": username,
                    "Role": user_data.get("role", "unknown"),
                    "Created": user_data.get("created_at", "unknown"),
                    "Permissions Count": len(user_data.get("permissions", []))
                }
                for username, user_data in users.items()
            ])
            st.dataframe(user_df, use_container_width=True)
        
        # Add new user
        with st.expander("➕ Add New User", expanded=False):
            with st.form("add_user_form_system"):
                new_username = st.text_input("Username", placeholder="Enter username")
                new_role = st.selectbox("Role", ["standard", "manager", "admin"])
                
                st.write("**Custom Permissions (optional):**")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**General Permissions:**")
                    perm_access = st.checkbox("Basic Access", value=True)
                    perm_chat = st.checkbox("Chat", value=True)
                    perm_upload = st.checkbox("Document Upload", value=True)
                    perm_delete = st.checkbox("Document Delete", value=False)
                
                with col2:
                    st.write("**Agent-Specific Permissions:**")
                    agent_permissions = {}
                    for agent_id, agent_config in st.session_state.agents.items():
                        st.write(f"**{agent_config['name']} ({agent_id}):**")
                        agent_permissions[agent_id] = {
                            "access": st.checkbox(f"{agent_id} Access", key=f"perm_{agent_id}_access"),
                            "chat": st.checkbox(f"{agent_id} Chat", key=f"perm_{agent_id}_chat"),
                            "upload": st.checkbox(f"{agent_id} Upload", key=f"perm_{agent_id}_upload"),
                            "delete": st.checkbox(f"{agent_id} Delete", key=f"perm_{agent_id}_delete")
                        }
                
                if st.form_submit_button("➕ Add User", type="primary"):
                    if new_username:
                        # Build permissions list
                        permissions = []
                        
                        # Add general permissions
                        if perm_access:
                            permissions.append("access")
                        if perm_chat:
                            permissions.append("chat")
                        if perm_upload:
                            permissions.append("document_upload")
                        if perm_delete:
                            permissions.append("document_delete")
                        
                        # Add agent-specific permissions
                        for agent_id, perms in agent_permissions.items():
                            if perms["access"]:
                                permissions.append(f"{agent_id}:access")
                            if perms["chat"]:
                                permissions.append(f"{agent_id}:chat")
                            if perms["upload"]:
                                permissions.append(f"{agent_id}:document_upload")
                            if perms["delete"]:
                                permissions.append(f"{agent_id}:document_delete")
                        
                        if st.session_state.user_manager.add_user(new_username, new_role, permissions):
                            st.success(f"✅ User '{new_username}' added successfully!")
                            st.rerun()
                        else:
                            st.error(f"❌ Failed to add user '{new_username}'")
                    else:
                        st.error("❌ Please enter a username")
        
        # Edit existing user permissions
        if users:
            with st.expander("✏️ Edit User Permissions", expanded=False):
                selected_user = st.selectbox("Select User to Edit", 
                                           options=list(users.keys()),
                                           key="edit_user_select")
                
                if selected_user:
                    user_data = users[selected_user]
                    current_permissions = user_data.get("permissions", [])
                    
                    st.write(f"**Current permissions for {selected_user}:**")
                    st.write(current_permissions)
                    
                    with st.form("edit_user_permissions"):
                        st.write("**Update Permissions:**")
                        
                        # General permissions
                        edit_access = st.checkbox("Basic Access", 
                                                value="access" in current_permissions,
                                                key="edit_access")
                        edit_chat = st.checkbox("Chat", 
                                              value="chat" in current_permissions,
                                              key="edit_chat")
                        edit_upload = st.checkbox("Document Upload", 
                                                 value="document_upload" in current_permissions,
                                                 key="edit_upload")
                        edit_delete = st.checkbox("Document Delete", 
                                                 value="document_delete" in current_permissions,
                                                 key="edit_delete")
                        
                        # Agent-specific permissions
                        st.write("**Agent-Specific Permissions:**")
                        agent_edit_permissions = {}
                        for agent_id, agent_config in st.session_state.agents.items():
                            st.write(f"**{agent_config['name']} ({agent_id}):**")
                            agent_edit_permissions[agent_id] = {
                                "access": st.checkbox(f"{agent_id} Access", 
                                                    value=f"{agent_id}:access" in current_permissions,
                                                    key=f"edit_{agent_id}_access"),
                                "chat": st.checkbox(f"{agent_id} Chat", 
                                                  value=f"{agent_id}:chat" in current_permissions,
                                                  key=f"edit_{agent_id}_chat"),
                                "upload": st.checkbox(f"{agent_id} Upload", 
                                                     value=f"{agent_id}:document_upload" in current_permissions,
                                                     key=f"edit_{agent_id}_upload"),
                                "delete": st.checkbox(f"{agent_id} Delete", 
                                                     value=f"{agent_id}:document_delete" in current_permissions,
                                                     key=f"edit_{agent_id}_delete")
                            }
                        
                        if st.form_submit_button("💾 Update Permissions", type="primary"):
                            # Build new permissions list
                            new_permissions = []
                            
                            # Add general permissions
                            if edit_access:
                                new_permissions.append("access")
                            if edit_chat:
                                new_permissions.append("chat")
                            if edit_upload:
                                new_permissions.append("document_upload")
                            if edit_delete:
                                new_permissions.append("document_delete")
                            
                            # Add agent-specific permissions
                            for agent_id, perms in agent_edit_permissions.items():
                                if perms["access"]:
                                    new_permissions.append(f"{agent_id}:access")
                                if perms["chat"]:
                                    new_permissions.append(f"{agent_id}:chat")
                                if perms["upload"]:
                                    new_permissions.append(f"{agent_id}:document_upload")
                                if perms["delete"]:
                                    new_permissions.append(f"{agent_id}:document_delete")
                            
                            if st.session_state.user_manager.update_user_permissions(selected_user, new_permissions):
                                st.success(f"✅ Permissions updated for '{selected_user}'!")
                                st.rerun()
                            else:
                                st.error(f"❌ Failed to update permissions for '{selected_user}'")
    
        # Delete user
        if users and len(users) > 1:  # Don't allow deleting the last user
            with st.expander("🗑️ Delete User", expanded=False):
                user_to_delete = st.selectbox("Select User to Delete", 
                                            options=[u for u in users.keys() if u != "admin"],
                                            key="delete_user_select")
                
                if user_to_delete:
                    st.warning(f"⚠️ This will permanently delete user '{user_to_delete}'")
                    if st.button("🗑️ Confirm Delete", type="secondary"):
                        if st.session_state.user_manager.delete_user(user_to_delete):
                            st.success(f"✅ User '{user_to_delete}' deleted successfully!")
                            st.rerun()
                        else:
                            st.error(f"❌ Failed to delete user '{user_to_delete}'")
        
        # Reset permissions - useful for testing
        with st.expander("🔄 Reset User System", expanded=False):
            st.warning("⚠️ This will reset all users and create default ones with correct permissions")
            if st.button("🔄 Reset User System", type="secondary"):
                try:
                    # Delete all users except admin
                    all_users = st.session_state.user_manager.get_all_users()
                    for username in all_users.keys():
                        if username != "admin":
                            st.session_state.user_manager.delete_user(username)
                    
                    # Create test users with proper permissions
                    test_users = [
                        ("testuser", "standard"),
                        ("manager1", "manager"),
                        ("standarduser", "standard")
                    ]
                    
                    for username, role in test_users:
                        st.session_state.user_manager.add_user(username, role)
                    
                    st.success("✅ User system reset successfully! Created test users with default passwords.")
                    st.info("Test users created: testuser, manager1, standarduser (all with password: username123)")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error resetting user system: {e}")
    
    # Azure Configuration
    st.write("### ☁️ Azure Configuration")
    with st.expander("Azure Service Settings"):
        st.write("**Current Azure Configuration:**")
        st.code(f"""
AZURE_CLIENT_ID=c7790b94-d830-4746-961f-8c715a380c5e
AZURE_CLIENT_SECRET=6Jl8Q~Kue3BfEbXdbc3O-68WVEIPZeNFD-Bkub2p
AZURE_TENANT_ID=7ae3526a-96fa-407a-9b02-9fe5bdff6217
REDIRECT_URI=https://egentapp-b4gqeudnc3h8emd3.westeurope-01.azurewebsites.net/
DEV_MODE=false
AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=egentst;...
USE_MANAGED_IDENTITY=true
AZURE_STORAGE_ACCOUNT_NAME=egentst
        """)
        
        st.info("💡 Azure configuration is managed through environment variables. Contact your system administrator to modify these settings.")
    
    # Application Settings
    st.write("### 📱 Application Settings")
    with st.form("app_settings"):
        st.write("**General Settings:**")
        max_file_size = st.number_input("Max File Size (MB)", value=10, min_value=1, max_value=100)
        session_timeout = st.number_input("Session Timeout (minutes)", value=60, min_value=15, max_value=480)
        auto_save_interval = st.number_input("Auto-save Interval (seconds)", value=30, min_value=10, max_value=300)
        
        st.write("**Chat Settings:**")
        max_message_length = st.number_input("Max Message Length", value=4000, min_value=100, max_value=10000)
        chat_history_limit = st.number_input("Chat History Limit", value=50, min_value=10, max_value=200)
        
        st.write("**Document Settings:**")
        supported_formats = st.multiselect("Supported File Formats", 
                                         options=["pdf", "docx", "txt", "xlsx", "pptx"], 
                                         default=["pdf", "docx", "txt"])
        
        if st.form_submit_button("💾 Save Settings", type="primary"):
            # Save settings to session state (in a real app, these would be saved to database)
            st.session_state.app_settings = {
                "max_file_size": max_file_size,
                "session_timeout": session_timeout,
                "auto_save_interval": auto_save_interval,
                "max_message_length": max_message_length,
                "chat_history_limit": chat_history_limit,
                "supported_formats": supported_formats
            }
            st.success("✅ Settings saved successfully!")
    
    # System Information
    st.write("### 📊 System Information")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Agents", len(st.session_state.agents))
    with col2:
        st.metric("Total Users", len(st.session_state.user_manager.get_all_users()))
    with col3:
        st.metric("Active Sessions", 1)  # This would be dynamic in a real app
    
    # Backup and Restore
    st.write("### 💾 Backup & Restore")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📥 Export Configuration", type="secondary"):
            import json
            config_data = {
                "agents": st.session_state.agents,
                "users": st.session_state.user_manager.get_all_users(),
                "settings": st.session_state.get("app_settings", {})
            }
            st.download_button(
                label="💾 Download Config",
                data=json.dumps(config_data, indent=2),
                file_name=f"azure_ai_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        uploaded_config = st.file_uploader("📤 Import Configuration", type="json")
        if uploaded_config and st.button("🔄 Restore Configuration"):
            try:
                import json
                config_data = json.load(uploaded_config)
                
                if "agents" in config_data:
                    # Ensure we always have a dictionary format
                    agents_data = config_data["agents"]
                    if isinstance(agents_data, dict):
                        st.session_state.agents = agents_data
                    elif isinstance(agents_data, list):
                        # Convert list to dict if needed (legacy format)
                        st.session_state.agents = {f"agent_{i}": agent for i, agent in enumerate(agents_data)}
                    else:
                        st.warning("Invalid agents format in configuration file")
                        st.session_state.agents = {}
                if "users" in config_data:
                    # For blob storage user manager, we need to update users individually
                    for username, user_data in config_data["users"].items():
                        if username not in st.session_state.user_manager.get_all_users():
                            st.session_state.user_manager.add_user(
                                username, 
                                user_data.get("role", "standard"),
                                user_data.get("permissions", {})
                            )
                if "settings" in config_data:
                    st.session_state.app_settings = config_data["settings"]
                
                st.success("✅ Configuration restored successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error restoring configuration: {str(e)}")
