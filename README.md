# 🤖 Azure Multi-Agent AI Platform

A comprehensive multi-agent Azure AI document management and chat system with role-based access control.

## 🌟 Features

### 🔐 Authentication System
- **Admin Login**: Full system access with user management capabilities
- **Azure User Login**: Role-based access with agent-specific permissions
- **Role-Based Access Control (RBAC)**: Granular permissions for each agent

### 🤖 Multi-Agent Architecture
- **6 Specialized AI Agents**:
  - 👥 **HR Assistant**: Human Resources and Employee Management
  - 💰 **Finance Assistant**: Financial Analysis and Accounting Support
  - 📈 **Sales Assistant**: Sales Support and Customer Relations
  - ⚖️ **Legal Assistant**: Legal Document Analysis and Compliance
  - 💻 **IT Support**: Technical Support and IT Operations
  - 📢 **Marketing Assistant**: Marketing Campaigns and Brand Management

### 📁 Document Management
- **Multi-format Support**: PDF, DOCX, TXT files
- **Azure Blob Storage**: Secure cloud storage with agent-specific containers
- **Azure AI Search**: Advanced document indexing and search capabilities
- **Upload/Download/Delete**: Full document lifecycle management

### 💬 Advanced Chat System
- **Agent-specific Conversations**: Each agent maintains separate chat history
- **Persistent Threads**: Conversation continuity across sessions
- **Export Functionality**: Save chat history for future reference
- **Real-time Responses**: Fast AI-powered responses with retry logic

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Azure subscription with AI Services
- Internet connection for Azure services

### Installation

1. **Clone or Download** the project files to your local machine

2. **Run the startup script**:
   ```bash
   python run_app.py
   ```
   
   This will automatically:
   - Install all required packages
   - Start the Streamlit application
   - Open your web browser

3. **Alternative Manual Start**:
   ```bash
   pip install -r requirements.txt
   streamlit run multi_agent_app.py
   ```

## 🔑 Login Credentials

### Admin Access (Full Permissions)
- **Username**: `admin`
- **Password**: `G5x!bQz2Lp9`

### Demo User (Limited Permissions)
- **Username**: `user1`
- **Password**: `azure_password`

## 🎯 Usage Guide

### 1. Login
- Choose between Admin Login or Azure User Login
- Enter credentials and click login

### 2. Dashboard
- View available AI agents
- See access permissions for each agent
- Click on any agent card to open the agent interface

### 3. Agent Interface
- **Chat Tab**: Communicate with the AI agent
- **Documents Tab**: Upload, view, and manage documents
- **Settings Tab**: View agent configuration and test connections

### 4. User Management (Admin Only)
- Access through "User Management" button on dashboard
- View current users and their permissions
- Add new users with custom agent permissions

## ⚙️ Configuration

### Azure Services Required
- **Azure AI Projects**: For AI agent functionality
- **Azure Blob Storage**: For document storage
- **Azure AI Search**: For document indexing and search

### Environment Configuration
The system uses the following Azure configuration:
```python
AZURE_CLIENT_ID=904b1d30-71da-4a0b-9394-78ec6b6c505a
AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=egentst;...
AZURE_SEARCH_SERVICE_ENDPOINT=https://egentaisearch.search.windows.net
# ... and more
```

## 🏗️ Architecture

### Core Components
- **`multi_agent_app.py`**: Main application logic and Azure integrations
- **`ui_components.py`**: User interface components and page layouts
- **`run_app.py`**: Startup script for easy deployment
- **`requirements.txt`**: Python dependencies

### Key Classes
- **`AgentManager`**: Manages agent configurations and operations
- **`UserManager`**: Handles authentication and authorization
- **`EnhancedAzureAIAgentClient`**: Azure AI client with document management
- **`DocumentProcessor`**: Processes different document formats

## 🔒 Security Features

### Authentication
- Secure password-based authentication
- Session management with Streamlit
- Role-based access control

### Authorization
- Agent-specific permissions (Access, Chat, Upload, Delete)
- Admin privileges for system management
- Granular permission matrix

### Data Security
- Azure Blob Storage encryption
- Secure API connections
- No credential hardcoding

## 📊 Permissions Matrix

| Permission Type | Description |
|----------------|-------------|
| **Access** | Can view and select the agent |
| **Chat** | Can communicate with the agent |
| **Upload** | Can upload documents to agent's storage |
| **Delete** | Can delete documents from agent's storage |

## 🛠️ Development

### File Structure
```
azure-multi-agent-platform/
├── multi_agent_app.py      # Main application
├── ui_components.py        # UI components
├── run_app.py             # Startup script
├── requirements.txt       # Dependencies
└── README.md             # This file
```

### Adding New Agents
1. Update `AgentManager._load_default_agents()` in `multi_agent_app.py`
2. Add agent configuration with unique ID, connection string, and container name
3. The system will automatically handle UI and permissions

### Customizing UI
- Modify CSS styles in `multi_agent_app.py` 
- Update UI components in `ui_components.py`
- Customize agent cards, colors, and layouts

## 📋 Requirements

### Python Packages
- `streamlit`: Web application framework
- `azure-ai-projects`: Azure AI integration
- `azure-identity`: Azure authentication
- `azure-storage-blob`: Blob storage operations
- `azure-search-documents`: Search functionality
- `PyPDF2`: PDF document processing
- `python-docx`: Word document processing
- `pandas`: Data manipulation and display

### System Requirements
- Windows/macOS/Linux
- Python 3.8+
- 4GB RAM minimum
- Internet connection for Azure services

## 🔧 Troubleshooting

### Common Issues

1. **Connection Errors**: Verify Azure credentials and network connectivity
2. **Permission Denied**: Check user permissions in User Management
3. **Document Upload Fails**: Ensure file formats are supported (PDF, DOCX, TXT)
4. **Agent Not Responding**: Test connection in Settings tab

### Debug Mode
Set `DEV_MODE=true` in configuration for additional logging and debug information.

## 🤝 Support

For technical support or questions:
1. Check the troubleshooting section
2. Review Azure service status
3. Verify credentials and permissions
4. Check application logs in terminal

## 📈 Performance Optimization

### Features Included
- **Lazy Loading**: Heavy libraries loaded only when needed
- **Session Caching**: Efficient state management
- **Connection Pooling**: Optimized Azure connections
- **Response Caching**: Faster repeat operations

### Best Practices
- Keep document sizes under 100MB for optimal performance
- Use specific search queries for better results
- Regularly clean up old documents
- Monitor Azure service quotas

## 🌐 Browser Compatibility

Supported browsers:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## 📄 License

This project is provided for demonstration and educational purposes. Ensure compliance with Azure terms of service and your organization's policies when using in production environments.
