from pymongo import MongoClient
from config import settings

def get_db():
    try:
        client = MongoClient(settings.database_url)
        db = client[settings.database_name]
        return db
    except Exception as e:
        print(e)
    
    client.close()