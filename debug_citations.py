"""
Detailed citation debugging script to understand the annotation structure
"""

import logging
import sys
import os
import json

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from streamlit_chatbot.py
from streamlit_chatbot import AzureAIAgentClient

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def debug_citation_structure():
    """Debug the citation annotation structure in detail"""
    
    # Default connection values for IT Support agent
    connection_string = "eastus2.api.azureml.ms;904b1d30-71da-4a0b-9394-78ec6b6c505a;egerg;egehubproject"
    agent_id = "asst_mEUu1oKSR4BUujGTR3kMj6Qw"
    
    try:
        print("🔍 Debugging citation annotation structure...")
        
        # Initialize client
        client = AzureAIAgentClient(connection_string, agent_id)
        print("✅ Client initialized successfully")
        
        # Create thread
        thread = client.create_thread()
        print(f"✅ Thread created: {thread.id}")
        
        # Test message
        test_message = "ege kimya fabrika direktörü kimdir?"
        print(f"📝 Sending test message: {test_message}")
        
        # Create user message
        client.client.agents.create_message(
            thread_id=thread.id,
            role="user",
            content=test_message
        )
        
        # Create and process run
        run = client.client.agents.create_and_process_run(
            thread_id=thread.id,
            agent_id=client.agent.id
        )
        
        # Get messages
        messages = client.client.agents.list_messages(thread_id=thread.id)
        text_messages = list(messages.text_messages)
        
        if text_messages:
            first_message = text_messages[0]
            
            print(f"\n📨 Message structure debug:")
            print(f"Message type: {type(first_message)}")
            
            # Debug text content
            if hasattr(first_message, 'text'):
                print(f"Text type: {type(first_message.text)}")
                if hasattr(first_message.text, 'value'):
                    print(f"Text value: {first_message.text.value}")
                
                # Debug annotations in detail
                if hasattr(first_message.text, 'annotations'):
                    annotations = first_message.text.annotations
                    print(f"\n🔍 Found {len(annotations)} annotations:")
                    
                    for i, annotation in enumerate(annotations):
                        print(f"\n--- Annotation {i} ---")
                        print(f"Type: {type(annotation)}")
                        print(f"Dir: {dir(annotation)}")
                        
                        # Try to get annotation as dict
                        try:
                            annotation_dict = annotation.as_dict() if hasattr(annotation, 'as_dict') else str(annotation)
                            print(f"As dict: {json.dumps(annotation_dict, indent=2, default=str)}")
                        except Exception as e:
                            print(f"Could not convert to dict: {e}")
                        
                        # Check all attributes
                        for attr in dir(annotation):
                            if not attr.startswith('_'):
                                try:
                                    value = getattr(annotation, attr)
                                    if not callable(value):
                                        print(f"{attr}: {value} (type: {type(value)})")
                                except Exception as e:
                                    print(f"{attr}: Error getting value - {e}")
                        
                        # Special handling for URL citation
                        if hasattr(annotation, 'url_citation'):
                            print(f"\n🌐 URL Citation details:")
                            url_citation = annotation.url_citation
                            print(f"URL Citation type: {type(url_citation)}")
                            print(f"URL Citation dir: {dir(url_citation)}")
                            
                            for attr in dir(url_citation):
                                if not attr.startswith('_'):
                                    try:
                                        value = getattr(url_citation, attr)
                                        if not callable(value):
                                            print(f"  {attr}: {value}")
                                    except Exception as e:
                                        print(f"  {attr}: Error - {e}")
            
            # Also check if there are file citation annotations
            if hasattr(first_message, 'file_citation_annotations'):
                citations = first_message.file_citation_annotations
                print(f"\n📎 Found {len(citations)} file citation annotations:")
                
                for i, citation in enumerate(citations):
                    print(f"\n--- File Citation {i} ---")
                    print(f"Type: {type(citation)}")
                    print(f"Dir: {dir(citation)}")
                    
                    try:
                        citation_dict = citation.as_dict() if hasattr(citation, 'as_dict') else str(citation)
                        print(f"As dict: {json.dumps(citation_dict, indent=2, default=str)}")
                    except Exception as e:
                        print(f"Could not convert to dict: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during debug: {e}")
        logger.exception("Debug failed")
        return False

if __name__ == "__main__":
    print("🔍 Starting detailed citation structure debugging...")
    success = debug_citation_structure()
    
    if success:
        print("\n✅ Debug completed!")
    else:
        print("\n❌ Debug failed!")
