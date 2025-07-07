"""
Alternative startup script for debugging Azure Web App issues
This script starts with the minimal test app first
"""

import os
import sys
import subprocess
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("debug_startup")

def test_minimal_streamlit():
    """Test if Streamlit works with minimal configuration"""
    
    port = os.environ.get('PORT', '8000')
    
    cmd = [
        sys.executable, "-m", "streamlit", "run", "test_streamlit.py",
        "--server.port", str(port),
        "--server.address", "0.0.0.0",
        "--server.headless", "true",
        "--logger.level", "debug"
    ]
    
    logger.info(f"🧪 Testing minimal Streamlit: {' '.join(cmd)}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Monitor for 30 seconds
        start_time = time.time()
        success = False
        
        for line in iter(process.stdout.readline, ''):
            if line:
                print(line.rstrip())
                
                if any(indicator in line for indicator in [
                    "Network URL:", "You can now view", "streamlit run"
                ]):
                    logger.info("✅ Minimal Streamlit test successful!")
                    success = True
                    break
                    
                if time.time() - start_time > 30:  # 30 second timeout
                    break
        
        process.terminate()
        return success
        
    except Exception as e:
        logger.error(f"❌ Minimal test failed: {e}")
        return False

def start_main_app():
    """Start the main application"""
    
    port = os.environ.get('PORT', '8000')
    
    # Setup environment
    os.environ['PYTHONUNBUFFERED'] = '1'
    
    cmd = [
        sys.executable, "-m", "streamlit", "run", "multi_agent_app.py",
        "--server.port", str(port),
        "--server.address", "0.0.0.0",
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
        "--server.enableCORS", "false",
        "--server.enableXsrfProtection", "false",
        "--logger.level", "debug"
    ]
    
    logger.info(f"🚀 Starting main app: {' '.join(cmd)}")
    
    # Run the main application
    subprocess.run(cmd)

def main():
    """Debug startup sequence"""
    
    logger.info("🐛 DEBUG STARTUP - Azure Web App")
    logger.info("=" * 50)
    
    # Environment info
    logger.info(f"Port: {os.environ.get('PORT', 'Not set')}")
    logger.info(f"Working dir: {os.getcwd()}")
    logger.info(f"Python: {sys.version}")
    
    # List files
    try:
        files = [f for f in os.listdir('.') if f.endswith('.py')]
        logger.info(f"Python files: {files}")
    except Exception as e:
        logger.error(f"Could not list files: {e}")
    
    # Test minimal Streamlit first
    logger.info("\n🧪 Step 1: Testing minimal Streamlit...")
    if test_minimal_streamlit():
        logger.info("✅ Minimal test passed, starting main app...")
    else:
        logger.warning("⚠️ Minimal test failed, but trying main app anyway...")
    
    # Start main application
    logger.info("\n🚀 Step 2: Starting main application...")
    start_main_app()

if __name__ == "__main__":
    main()
