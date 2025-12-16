import redis
from config import settings
def connect_to_redis():
    """Establish connection to Redis server with username and password."""
    try:
        client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_database,
            username=settings.redis_username,  
            password=settings.redis_password,  
            decode_responses=True
        )
        # Test connection
        client.ping()
        print("Successfully connected to Redis")
        return client
    except redis.AuthenticationError as e:
        print(f"Authentication failed: {e}")
        return None
    except redis.ConnectionError as e:
        print(f"Failed to connect to Redis: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None