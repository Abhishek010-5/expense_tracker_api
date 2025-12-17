# app/extension.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.redisdb import connect_to_redis

redis_client = connect_to_redis()

if redis_client is None:
    raise RuntimeError("Cannot initialize Flask-Limiter: Failed to connect to Redis")

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://",  # selects Redis backend
    storage_options={"connection_pool": redis_client.connection_pool},
)