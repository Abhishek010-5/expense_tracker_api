from pymongo import MongoClient
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Global client - initialized only once
_client = None

def get_mongo_client() -> MongoClient:
    global _client
    
    if _client is None:
        try:
            _client = MongoClient(
                settings.database_url,
                maxPoolSize=50,
                minPoolSize=5,
                maxIdleTimeMS=30000,          
                connectTimeoutMS=20000,
                serverSelectionTimeoutMS=5000,
                retryWrites=True,
                retryReads=True,
            )
            # Optional: verify connection at startup
            _client.admin.command('ping')
            logger.info("MongoDB connection pool initialized")
        except Exception as e:
            logger.critical("Failed to connect to MongoDB", exc_info=True)
            raise
    
    return _client


def get_db():
    """Get database instance - do NOT close the client"""
    client = get_mongo_client()
    return client[settings.database_name]