import redis
import logging

from app.config import settings

logger = logging.getLogger(__name__)

def connect_to_redis():
    """Establish connection to Redis server with username and password."""
    try:
        client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            decode_responses=True,
            username=settings.redis_username,  
            password=settings.redis_password,  
        )
        # Test connection
        client.ping()
        logger.debug("Successfully connected to Redis")
        return client
    except redis.AuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
        return None
    except redis.ConnectionError as e:
        logger.error(f"Failed to connect to Redis: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return None