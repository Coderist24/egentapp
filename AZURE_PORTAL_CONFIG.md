# Azure Portal Manuel Konfigürasyon Rehberi

## 🎯 Azure Web App Configuration

### 1. Azure Portal'da Web App'inizi bulun
- Azure Portal > App Services > `egentapp-b4gqeudnc3h8emd3`

### 2. Configuration > General Settings
**Startup Command** bölümüne:
```
python app_startup.py
```

### 3. Configuration > Application Settings
Aşağıdaki Key-Value çiftlerini **"+ New application setting"** ile ekleyin:

#### 🔐 Azure Authentication
```
Name: AZURE_CLIENT_ID
Value: c7790b94-d830-4746-961f-8c715a380c5e

Name: AZURE_TENANT_ID  
Value: 7ae3526a-96fa-407a-9b02-9fe5bdff6217

Name: AZURE_CLIENT_SECRET
Value: 6Jl8Q~Kue3BfEbXdbc3O-68WVEIPZeNFD-Bkub2p
```

#### 🌐 Web App Configuration
```
Name: WEBSITE_SITE_NAME
Value: egentapp-b4gqeudnc3h8emd3

Name: PORT
Value: 8000

Name: PYTHONPATH
Value: /home/site/wwwroot

Name: PYTHONUNBUFFERED
Value: 1
```

#### 📦 Platform Settings
```
Name: WEBSITE_RUN_FROM_PACKAGE
Value: 1

Name: SCM_DO_BUILD_DURING_DEPLOYMENT
Value: true
```

#### 🎨 Streamlit Configuration
```
Name: STREAMLIT_SERVER_PORT
Value: 8000

Name: STREAMLIT_SERVER_ADDRESS
Value: 0.0.0.0

Name: STREAMLIT_BROWSER_GATHER_USAGE_STATS
Value: false

Name: STREAMLIT_SERVER_HEADLESS
Value: true

Name: STREAMLIT_SERVER_ENABLE_CORS
Value: false

Name: STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION
Value: false
```

### 4. Kaydet ve Restart
1. **"Save"** butonuna tıklayın
2. **"Restart"** butonuna tıklayın
3. Web App'in yeniden başlamasını bekleyin

### 5. Test
- Web App URL'i: `https://egentapp-b4gqeudnc3h8emd3.westeurope-01.azurewebsites.net/`
- Login ekranının geldiğini kontrol edin

### 6. Log Monitoring
Azure Portal'da:
- **Monitoring > Log stream** açın
- Uygulamanın başlatılma sürecini izleyin

## 🔧 Otomatik Konfigürasyon Alternatifleri

### PowerShell (Windows)
```powershell
.\azure-config.ps1
```

### Bash (Linux/Mac/WSL)
```bash
chmod +x azure-config.sh
./azure-config.sh
```

### Azure CLI (Manual)
```bash
# Resource group adınızı değiştirin
RESOURCE_GROUP="your-resource-group-name"

az webapp config appsettings set \
  --name egentapp-b4gqeudnc3h8emd3 \
  --resource-group $RESOURCE_GROUP \
  --settings @azure-app-settings.env
```

## 🚨 Troubleshooting

### Uygulama başlamıyorsa:
1. Startup command doğru mu? (`python app_startup.py`)
2. Tüm environment variables set edildi mi?
3. Log stream'de hata var mı?

### Login ekranı gelmiyorsa:
1. PORT environment variable set edildi mi?
2. STREAMLIT_SERVER_ADDRESS = 0.0.0.0 mi?
3. Web App restart edildi mi?

### Authentication çalışmıyorsa:
1. AZURE_CLIENT_ID, TENANT_ID, CLIENT_SECRET doğru mu?
2. Azure AD App Registration'da redirect URI doğru mu?
3. Client Secret expire olmadı mı?
