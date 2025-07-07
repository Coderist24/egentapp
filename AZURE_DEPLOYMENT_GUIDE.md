# Azure Web App Deployment - Troubleshooting Guide

## 🔧 Hızlı Çözüm Adımları

### 1. Azure Portal Configuration
Azure Portal'da Web App'inizin **Configuration** > **General Settings** bölümünde:
- **Startup Command**: `python app_startup.py`
- **Stack**: Python 3.11

### 2. Application Settings
Azure Portal'da **Configuration** > **Application Settings**'e şu değerleri ekleyin:

```
PORT=8000
PYTHONPATH=/home/site/wwwroot
PYTHONUNBUFFERED=1
WEBSITE_RUN_FROM_PACKAGE=1
SCM_DO_BUILD_DURING_DEPLOYMENT=true

# Azure Authentication
AZURE_CLIENT_ID=c7790b94-d830-4746-961f-8c715a380c5e
AZURE_TENANT_ID=7ae3526a-96fa-407a-9b02-9fe5bdff6217
AZURE_CLIENT_SECRET=6Jl8Q~Kue3BfEbXdbc3O-68WVEIPZeNFD-Bkub2p

# Streamlit Settings
STREAMLIT_SERVER_HEADLESS=true
STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
```

### 3. Log Monitoring
```bash
# Canlı logları izleme
az webapp log tail --name egentapp --resource-group your-resource-group

# Log stream'i etkinleştirme
az webapp log config --name egentapp --resource-group your-resource-group --web-server-logging filesystem
```

## 🚨 Yaygın Sorunlar ve Çözümler

### Problem 1: Uygulama Başlamıyor
**Semptomlar**: HTTP 500 hatası, sayfa yüklenmiyor
**Çözüm**:
1. Startup Command'ın doğru olduğunu kontrol edin: `python app_startup.py`
2. Tüm dosyaların uploaded olduğunu kontrol edin
3. Log stream'de hata mesajlarını kontrol edin

### Problem 2: Login Ekranı Gelmiyor
**Semptomlar**: Beyaz sayfa, içerik yüklenmiyor
**Çözüm**:
1. Port binding'i kontrol edin (PORT environment variable)
2. Streamlit headless mode'un aktif olduğunu kontrol edin
3. CORS ayarlarını kontrol edin

### Problem 3: MSAL Authentication Hatası
**Semptomlar**: Redirect URI mismatch
**Çözüm**:
1. Azure AD App Registration'da redirect URI'yi güncelleyin
2. Environment variables'ın doğru set edildiğini kontrol edin

## 📋 Deployment Checklist

- [ ] ✅ Startup Command: `python app_startup.py`
- [ ] ✅ PORT environment variable set
- [ ] ✅ PYTHONPATH environment variable set  
- [ ] ✅ Azure authentication variables set
- [ ] ✅ All Python files uploaded
- [ ] ✅ requirements.txt uploaded
- [ ] ✅ Log stream monitoring enabled

## 🔍 Debug Commands

### Azure CLI Commands
```bash
# Web App status
az webapp show --name egentapp --resource-group your-rg --query "state"

# Environment variables
az webapp config appsettings list --name egentapp --resource-group your-rg

# Restart app
az webapp restart --name egentapp --resource-group your-rg
```

### Streamlit Debug Commands
Uygulamanın içinde debug için:
```python
import streamlit as st
st.write("Debug info:")
st.write(f"Port: {os.environ.get('PORT', 'Not set')}")
st.write(f"Address: {os.environ.get('STREAMLIT_SERVER_ADDRESS', 'Not set')}")
st.write(f"Working Dir: {os.getcwd()}")
```

## 🔄 Deployment Steps

1. **Code Upload**: Tüm dosyaları Azure Web App'e upload edin
2. **Configuration**: Azure Portal'da startup command ve environment variables'ları set edin
3. **Restart**: Web App'i restart edin
4. **Monitor**: Log stream'i açık tutarak startup process'ini izleyin
5. **Test**: Uygulamanın login sayfasının açıldığını kontrol edin

## 💡 Performance Tips

1. **Cold Start**: İlk açılış 30-60 saniye sürebilir
2. **Always On**: Production'da "Always On" özelliğini aktif edin
3. **Scale Up**: Daha büyük instance size kullanın (B2 veya daha üstü)

## 🆘 Acil Durum Çözümleri

### Uygulama Hiç Açılmıyorsa:
1. Azure Portal'da "Restart" butonuna basın
2. Startup command'ı kontrol edin
3. Deployment center'dan son deployment'ı kontrol edin

### Login Ekranı Gözükmüyorsa:
1. Browser cache'ini temizleyin
2. Farklı browser deneyin
3. Network tools'da HTTP response'ları kontrol edin

### Authentication Çalışmıyorsa:
1. Azure AD App Registration ayarlarını kontrol edin
2. Redirect URI'yi güncelleyin
3. Client Secret'ın expire olmadığını kontrol edin
