#!/usr/bin/env python3
"""
Script to recreate Azure Search index with vector embeddings
This will delete the existing index and recreate it with proper vector support
"""

import logging
from azure_utils import AzureConfig
from azure.search.documents.indexes import SearchIndexClient
from azure.core.credentials import AzureKeyCredential

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def recreate_index_with_vectors():
    """Delete and recreate index with vector capabilities"""
    try:
        print("🔄 Recreating Azure Search Index with Vector Support")
        print("=" * 60)
        
        # Initialize configuration
        config = AzureConfig()
        
        if not config.search_endpoint or not config.search_admin_key:
            print("❌ Search endpoint or admin key not configured")
            return False
            
        # Initialize search index client
        credential = AzureKeyCredential(config.search_admin_key)
        search_index_client = SearchIndexClient(
            endpoint=config.search_endpoint,
            credential=credential
        )
        
        index_name = "it-search-index"
        
        print(f"🗑️ Deleting existing index: {index_name}")
        try:
            search_index_client.delete_index(index_name)
            print(f"✅ Index '{index_name}' deleted successfully")
        except Exception as e:
            if "not found" in str(e).lower():
                print(f"ℹ️ Index '{index_name}' not found, will create new one")
            else:
                print(f"⚠️ Error deleting index: {e}")
        
        print(f"\n🏗️ Creating new index with vector capabilities: {index_name}")
        
        # Import required classes
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
        
        result = search_index_client.create_index(index)
        print(f"✅ Search index '{index_name}' created successfully with vector capabilities!")
        
        print("\n📊 Index Configuration:")
        print(f"   • Fields: {len(fields)}")
        print("   • Vector Search: ✅ Enabled (1536 dimensions)")
        print("   • Semantic Search: ✅ Enabled")
        print("   • Vector Profile: content-vector-profile")
        print("   • HNSW Algorithm: content-hnsw")
        
        print("\n" + "=" * 60)
        print("🎉 Index recreation completed!")
        print("💡 Now upload documents to see vector embeddings in action")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to recreate index: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    recreate_index_with_vectors()
