"""
UI Components for Multi-Agent Azure AI Platform
Contains all the user interface functions and components
"""

import streamlit as st
import pandas as pd
import os
from datetime import datetime
from typing import Dict, List

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

            # --- DEBUG: Print current URL and query params ---
            st.markdown("---")
            st.info(f"**DEBUG:** Current page URL: {st.experimental_get_query_params()}")
            st.info(f"**DEBUG:** Redirect URI in use: {REDIRECT_URI}")
            st.info(f"**DEBUG:** AUTHORITY: {AUTHORITY}")
            
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
                st.info(f"**DEBUG:** Auth URL: {auth_url}")
                st.markdown(f"[Microsoft ile Giriş Yap]({auth_url})")

                # Callback: URL'de kod varsa token al
                query_params = st.experimental_get_query_params()
                if "code" in query_params:
                    code = query_params["code"][0]
                    st.info(f"**DEBUG:** Received code: {code}")
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
                else:
                    st.warning("**DEBUG:** No 'code' parameter found in URL after redirect. If you just logged in, check that your redirect URI matches exactly in Azure Portal and that your app is running at the correct URL.")
            except Exception as e:
                st.error(f"❌ Azure AD authentication hatası: {str(e)}")
                st.info("Lütfen Azure AD ayarlarınızı kontrol edin.")
            
        # Azure AD login help
        st.markdown("---")
        st.markdown("### ℹ️ Azure AD Giriş Bilgileri")
        st.info("""
        Azure AD kimlik doğrulama sistemi için:
        
        - Geçerli bir Azure Active Directory hesabınız olmalıdır
        - Hesabınızın bu uygulamaya erişim yetkisi olmalıdır
        - MFA (çok faktörlü kimlik doğrulama) desteklenir
        - Güvenli OAuth2 Authorization Code Flow kullanılır
        """)
        st.success("""
        ✅ Bu giriş yöntemi MFA destekler ve modern Azure AD güvenlik standartlarına uygundur.
        """)

def show_dashboard():
    """Display the main dashboard with agent selection"""
    
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
    
    # Create agent grid
    agents = st.session_state.agents
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
                        🔍 Index: {agent_config['search_index']}<br>
                        📂 Categories: {', '.join(agent_config['categories'])}
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
                    index_name = agent_config['search_index']
                    
                    success_count = 0
                    indexed_count = 0
                    error_details = []
                    
                    with st.spinner("Uploading and indexing documents..."):
                        for uploaded_file in uploaded_files:
                            try:
                                file_content = uploaded_file.read()
                                
                                # Upload and index document
                                result = client.upload_and_index_document(
                                    container_name,
                                    uploaded_file.name,
                                    file_content,
                                    uploaded_file.type or "application/octet-stream",
                                    index_name
                                )
                                
                                if result['success']:
                                    success_count += 1
                                    if result['indexed']:
                                        indexed_count += 1
                                    else:
                                        error_details.append(f"📁 {uploaded_file.name}: Uploaded but indexing failed")
                                else:
                                    error_details.append(f"❌ {uploaded_file.name}: {result.get('message', 'Upload failed')}")
                                    
                            except Exception as file_error:
                                error_details.append(f"💥 {uploaded_file.name}: {str(file_error)}")
                    
                    # Show detailed results
                    if success_count == len(uploaded_files):
                        if indexed_count == success_count:
                            st.success(f"✅ Successfully uploaded and indexed {success_count}/{len(uploaded_files)} files!")
                            st.info("🔍 Files are now searchable with vector embeddings for enhanced semantic search")
                        else:
                            st.warning(f"⚠️ Uploaded {success_count}/{len(uploaded_files)} files, but only {indexed_count} were indexed successfully")
                            if error_details:
                                with st.expander("📋 View Details"):
                                    for detail in error_details:
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
    
    # Document search section
    st.subheader("🔍 Search Documents")
    
    search_col1, search_col2 = st.columns([3, 1])
    with search_col1:
        search_query = st.text_input(
            "Search in document content",
            placeholder="Enter keywords to search...",
            key=f"search_query_{agent_id}"
        )
    
    with search_col2:
        search_button = st.button("🔍 Search", key=f"search_btn_{agent_id}")
    
    # Perform search if query is provided
    if search_button and search_query.strip():
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
            index_name = agent_config['search_index']
            
            with st.spinner("Searching documents..."):
                search_results = client.search_documents(search_query, index_name, top=10)
            
            if search_results:
                st.success(f"Found {len(search_results)} results for '{search_query}'")
                
                # Show search type info
                if search_results and search_results[0].get('search_type'):
                    search_type = search_results[0]['search_type']
                    if search_type == 'hybrid':
                        st.info("🤖 Using AI-powered hybrid search (text + semantic vector matching)")
                    else:
                        st.info("📝 Using traditional text search")
                
                for idx, result in enumerate(search_results):
                    # Enhanced display for vector search results
                    score_display = f"{result['score']:.3f}"
                    reranker_score = result.get('reranker_score')
                    
                    title = f"📄 {result['filename']}"
                    if reranker_score:
                        title += f" (Score: {score_display}, Semantic: {reranker_score:.3f})"
                    else:
                        title += f" (Score: {score_display})"
                    
                    with st.expander(title):
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.write(f"**Container:** {result['container_name']}")
                            st.write(f"**Type:** {result.get('content_type', 'Unknown')}")
                            if result.get('last_modified'):
                                st.write(f"**Modified:** {result['last_modified']}")
                            if result.get('search_type'):
                                search_icon = "🤖" if result['search_type'] == 'hybrid' else "📝"
                                st.write(f"**Search Type:** {search_icon} {result['search_type'].title()}")
                        
                        with col2:
                            st.metric("Relevance Score", score_display)
                            if reranker_score:
                                st.metric("Semantic Score", f"{reranker_score:.3f}")
                        
                        # Show content preview
                        if result.get('content'):
                            st.markdown("**Content Preview:**")
                            st.text_area(
                                "Content",
                                value=result['content'],
                                height=100,
                                key=f"search_content_{agent_id}_{idx}",
                                disabled=True
                            )
                        
                        # Show highlights if available
                        if result.get('highlights'):
                            st.markdown("**Highlighted matches:**")
                            for field, highlights in result['highlights'].items():
                                if highlights:  # Only show non-empty highlights
                                    st.markdown(f"**{field}:** {', '.join(highlights[:3])}")
            else:
                st.info(f"No documents found containing '{search_query}'")
                st.write("💡 **Tips for better search results:**")
                st.write("• Try different keywords or phrases")
                st.write("• Use specific terms related to your content")
                st.write("• For semantic search, try asking questions or using natural language")
                
        except Exception as e:
            st.error(f"❌ Search failed: {str(e)}")
    
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
                                if client.delete_document(container_name, doc['name']):
                                    st.success(f"✅ Deleted {doc['name']}")
                                    st.rerun()
                                else:
                                    st.error(f"❌ Failed to delete {doc['name']}")
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
        st.code(f"Search Index: {agent_config['search_index']}")
    
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
    """Display comprehensive settings interface for admin users"""
    
    if st.session_state.user_role != "admin":
        st.error("⚠️ Admin access required")
        return
    
    # Header
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown('<h1 class="main-header">⚙️ Settings</h1>', unsafe_allow_html=True)
    with col2:
        if st.button("🏠 Back to Dashboard"):
            st.session_state.current_page = "dashboard"
            st.rerun()
    
    # Settings tabs
    tab1, tab2, tab3 = st.tabs(["👥 User Management", "🤖 Agent Configuration", "🔧 System Settings"])
    
    with tab1:
        show_user_management_tab()
    
    with tab2:
        show_agent_configuration_tab()
    
    with tab3:
        show_system_settings_tab()

def show_user_management_tab():
    """User management tab content"""
    st.subheader("📋 Current Users")
    
    users = st.session_state.user_manager.users
    agents = st.session_state.agents
    
    for username, user_data in users.items():
        with st.expander(f"👤 {username} ({user_data['role']})"):
            st.write(f"**Role:** {user_data['role']}")
            
            if user_data['role'] != 'admin':
                st.write("**Agent Permissions:**")
                
                # Permission matrix
                permission_data = []
                for agent_id, agent_config in agents.items():
                    user_perms = user_data.get('permissions', {}).get(agent_id, {})
                    permission_data.append({
                        'Agent': agent_config['name'],
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
                    st.write("**Edit Permissions:**")
                    with st.form(f"edit_perms_{username}"):
                        updated_permissions = {}
                        
                        for agent_id, agent_config in agents.items():
                            st.write(f"**{agent_config['name']}**")
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
                            if st.form_submit_button("💾 Save Changes", type="primary"):
                                st.session_state.user_manager.users[username]['permissions'] = updated_permissions
                                st.session_state[f"editing_{username}"] = False
                                st.success("✅ Permissions updated!")
                                st.rerun()
                        with col2:
                            if st.form_submit_button("❌ Cancel"):
                                st.session_state[f"editing_{username}"] = False
                                st.rerun()
            else:
                st.success("👑 Full admin access to all agents and features")
            
            # Delete user button (except for admin)
            if username != "admin":
                if st.button(f"🗑️ Delete User", key=f"delete_{username}", type="secondary"):
                    del st.session_state.user_manager.users[username]
                    st.success(f"🗑️ User {username} deleted!")
                    st.rerun()
    
    # Add new user section
    st.markdown("---")
    st.subheader("➕ Add New User")
    
    with st.form("add_user"):
        new_username = st.text_input("Username")
        new_role = st.selectbox("Role", ["standard", "admin"])
        
        if new_role == "standard":
            st.write("**Agent Permissions:**")
            new_permissions = {}
            
            for agent_id, agent_config in agents.items():
                st.write(f"**{agent_config['name']}**")
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    access = st.checkbox("Access", key=f"new_access_{agent_id}")
                with col2:
                    chat = st.checkbox("Chat", key=f"new_chat_{agent_id}")
                with col3:
                    upload = st.checkbox("Upload", key=f"new_upload_{agent_id}")
                with col4:
                    delete = st.checkbox("Delete", key=f"new_delete_{agent_id}")
                
                new_permissions[agent_id] = {
                    'access': access,
                    'chat': chat,
                    'document_upload': upload,
                    'document_delete': delete
                }
        
        submitted = st.form_submit_button("Add User", type="primary")
        
        if submitted and new_username:
            if new_username not in users:
                new_user = {
                    "username": new_username,
                    "role": new_role,
                    "permissions": new_permissions if new_role == "standard" else {"all_agents": {"access": True, "chat": True, "document_upload": True, "document_delete": True, "admin": True}}
                }
                
                st.session_state.user_manager.users[new_username] = new_user
                st.success(f"✅ User {new_username} added successfully!")
                st.rerun()
            else:
                st.error("❌ Username already exists")
        elif submitted:
            st.error("❌ Please enter a username")

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
                st.write(f"- **Search Index:** {agent_config['search_index']}")
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
                        new_icon = st.text_input("Icon", value=agent_config['icon'], key=f"edit_icon_{agent_id}")
                        new_color = st.color_picker("Color", value=agent_config['color'], key=f"edit_color_{agent_id}")
                    
                    with col2:
                        new_container = st.text_input("Container Name", value=agent_config['container_name'], key=f"edit_container_{agent_id}")
                        new_search_index = st.text_input("Search Index", value=agent_config['search_index'], key=f"edit_search_{agent_id}")
                        new_connection_string = st.text_input("Azure Connection String", value=agent_config['connection_string'], type="password", key=f"edit_conn_{agent_id}")
                        new_agent_id = st.text_input("Agent ID", value=agent_config['agent_id'], key=f"edit_agent_id_{agent_id}")
                    
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
                                "agent_id": new_agent_id
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
            agent_icon = st.text_input("Icon (emoji or Unicode)", value="🤖")
            agent_color = st.color_picker("Color", value="#0078d4")
        
        with col2:
            container_name = st.text_input("Container Name")
            search_index = st.text_input("Search Index")
            connection_string = st.text_input("Azure Connection String", type="password")
            agent_id = st.text_input("Agent ID")
        
        categories = st.text_input("Categories (comma-separated)", placeholder="e.g., documents, reports, policies")
        
        if st.form_submit_button("Add Agent", type="primary"):
            if agent_name and container_name and search_index and connection_string and agent_id:
                new_agent_id = agent_name.lower().replace(" ", "_")
                
                if new_agent_id not in agents:
                    st.session_state.agents[new_agent_id] = {
                        "name": agent_name,
                        "description": agent_description,
                        "icon": agent_icon,
                        "color": agent_color,
                        "container_name": container_name,
                        "search_index": search_index,
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
AZURE_SEARCH_SERVICE_ENDPOINT=https://egentaisearch.search.windows.net
AZURE_SEARCH_ADMIN_KEY=Hz01153KXk45lVNXNT0QJIHq279xngUA2OSKMkgVlKAzSeAZzbvb
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
        st.metric("Total Users", len(st.session_state.user_manager.users))
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
                "users": st.session_state.user_manager.users,
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
                    st.session_state.agents = config_data["agents"]
                if "users" in config_data:
                    st.session_state.user_manager.users = config_data["users"]
                if "settings" in config_data:
                    st.session_state.app_settings = config_data["settings"]
                
                st.success("✅ Configuration restored successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error restoring configuration: {str(e)}")
