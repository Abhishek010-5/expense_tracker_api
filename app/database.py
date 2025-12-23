from pymongo import MongoClient
from app.config import settings
import logging

logger = logging.getLogger(__name__)
def get_db():
    try:
        client = MongoClient(settings.database_url)
        db = client[settings.database_name]
        return db
    except Exception as e:
        logger.error(str(e))
    
    client.close()