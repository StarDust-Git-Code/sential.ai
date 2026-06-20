import os
import time
import json
import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted, InvalidArgument

KEYS_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".sentinel_keys.json")

class APIKeyManager:
    def __init__(self, keys=None):
        self.keys = []
        # Load cached keys first
        self._load_cached_keys()
        # Then add any explicitly passed keys
        if keys:
            for k in keys:
                self.add_key(k)
        if not self.keys:
            env_key = os.environ.get("GEMINI_API_KEY")
            if env_key:
                self.add_key(env_key)
        self.current_index = 0

    def add_key(self, key: str):
        key = key.strip()
        if key and key not in self.keys:
            self.keys.append(key)
            self._save_cached_keys()

    def get_current_key(self):
        if not self.keys:
            return None
        return self.keys[self.current_index]

    def rotate_key(self):
        if not self.keys:
            return False
        self.current_index = (self.current_index + 1) % len(self.keys)
        return True

    def count(self):
        return len(self.keys)

    def _load_cached_keys(self):
        try:
            if os.path.exists(KEYS_CACHE_FILE):
                with open(KEYS_CACHE_FILE, "r") as f:
                    data = json.load(f)
                for k in data.get("keys", []):
                    if k and k not in self.keys:
                        self.keys.append(k)
        except Exception:
            pass

    def _save_cached_keys(self):
        try:
            with open(KEYS_CACHE_FILE, "w") as f:
                json.dump({"keys": self.keys}, f)
        except Exception:
            pass

    def execute_with_retry(self, func, *args, **kwargs):
        if not self.keys:
            raise ValueError("No API keys available.")

        attempts = 0
        max_attempts = len(self.keys) * 2 
        
        while attempts < max_attempts:
            key = self.get_current_key()
            genai.configure(api_key=key)
            try:
                return func(*args, **kwargs)
            except (ResourceExhausted, InvalidArgument):
                self.rotate_key()
                attempts += 1
                time.sleep(1) 
            except Exception as e:
                raise e
        
        raise Exception("All API keys exhausted their quotas or failed.")
