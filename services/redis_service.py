import json
import redis
import random
import traceback
from typing import List, Dict
from config.settings import settings
from config.redis_config import pool, get_redis_pool

def get_redis_hash_values(key: str, hash: str = None, db: int = 0, all_files: bool = False) -> bool:
    try:
        redis_client = get_redis_pool(pool)
        if hash is None:
            all_files = True
        if not redis_client.exists(key):
            print(f"Key: '{key}', does not exist in Redis")
            return False
        values =  redis_client.hgetall(key) if all_files else redis_client.hget(key, hash)
        if values is not None:
            values = {k.decode('utf-8'): json.loads(v.decode('utf-8')) for k, v in values.items()} if all_files else json.loads(values.decode('utf-8'))
            print(f"Successfully retrieved value for key: '{key}' and hash: '{hash}' from Redis DB: {db}")
            return values
        print(f"No values found for key: '{key}' and hash: '{hash}' from Redis DB: {db}")
        return False 
    except redis.RedisError as e:
        print(f"Failed to get value for key: '{key}' from Redis DB: {db} => {str(e)}\n\n{traceback.format_exc()}")
        return False