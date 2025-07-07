#!/bin/bash

# Azure Web App Configuration Script (Bash)
# Bu script'i bash'de çalıştırarak environment variables'ları Azure Web App'e set edebilirsiniz

RESOURCE_GROUP="your-resource-group-name"  # Resource group adınızı buraya yazın
WEB_APP_NAME="egentapp-b4gqeudnc3h8emd3"

echo "🔧 Azure Web App Configuration Script"
echo "================================================"

# Azure authentication check
echo "🔍 Azure CLI authentication kontrol ediliyor..."
if ! az account show > /dev/null 2>&1; then
    echo "❌ Azure CLI'ye giriş yapmanız gerekiyor!"
    echo "Lütfen 'az login' komutunu çalıştırın."
    exit 1
fi

echo "✅ Azure CLI authenticated"

# Application Settings ayarlama
echo "📝 Application Settings ayarlanıyor..."

az webapp config appsettings set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    AZURE_CLIENT_ID="c7790b94-d830-4746-961f-8c715a380c5e" \
    AZURE_TENANT_ID="7ae3526a-96fa-407a-9b02-9fe5bdff6217" \
    AZURE_CLIENT_SECRET="6Jl8Q~Kue3BfEbXdbc3O-68WVEIPZeNFD-Bkub2p" \
    WEBSITE_SITE_NAME="egentapp-b4gqeudnc3h8emd3" \
    PORT="8000" \
    PYTHONPATH="/home/site/wwwroot" \
    PYTHONUNBUFFERED="1" \
    WEBSITE_RUN_FROM_PACKAGE="1" \
    SCM_DO_BUILD_DURING_DEPLOYMENT="true" \
    STREAMLIT_SERVER_PORT="8000" \
    STREAMLIT_SERVER_ADDRESS="0.0.0.0" \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS="false" \
    STREAMLIT_SERVER_HEADLESS="true" \
    STREAMLIT_SERVER_ENABLE_CORS="false" \
    STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION="false" \
  --output none

if [ $? -eq 0 ]; then
    echo "✅ Application settings configured successfully"
else
    echo "❌ Failed to configure application settings"
    exit 1
fi

# Startup Command ayarlama
echo "🚀 Startup command ayarlanıyor..."
az webapp config set \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --startup-file "python app_startup.py" \
  --output none

if [ $? -eq 0 ]; then
    echo "✅ Startup command set: python app_startup.py"
else
    echo "❌ Failed to set startup command"
fi

# Web App restart
echo "🔄 Web App restart ediliyor..."
az webapp restart \
  --name $WEB_APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --output none

if [ $? -eq 0 ]; then
    echo "✅ Web App restarted successfully"
else
    echo "❌ Failed to restart Web App"
fi

echo "================================================"
echo "🎉 Configuration completed!"
echo "🌐 Web App URL: https://$WEB_APP_NAME.azurewebsites.net"
echo "📋 Log monitoring: az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"

# Log monitoring seçeneği
read -p "📋 Canlı logları açmak ister misiniz? (y/n): " open_logs
if [[ $open_logs == "y" || $open_logs == "Y" ]]; then
    echo "📋 Log stream açılıyor... (Ctrl+C ile kapatabilirsiniz)"
    az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP
fi
