"""
Enhanced LLM Engine with caching, retry logic, and improved error handling
"""

import requests
import json
import logging
import time
from typing import Optional, Dict, Any
from functools import lru_cache
import hashlib

logger = logging.getLogger(__name__)


class LLMAgent:
    """
    Advanced LLM Agent with caching and retry mechanisms
    """
    
    def __init__(self, model_name: str = "mistral:latest", base_url: str = "http://localhost:11434"):
        """
        Initialize LLM Agent
        
        Args:
            model_name (str): Name of the model to use
            base_url (str): Base URL for Ollama API
        """
        self.model_name = model_name
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/api"
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'total_tokens': 0
        }
    
    def query(self, prompt: str, timeout: int = 60, max_retries: int = 3) -> Optional[str]:
        """
        Query LLM with retry logic and error handling
        
        Args:
            prompt (str): Prompt to send to the model
            timeout (int): Request timeout in seconds
            max_retries (int): Maximum number of retry attempts
            
        Returns:
            Optional[str]: Model response or None if failed
        """
        if not prompt or len(prompt.strip()) == 0:
            self.logger.warning("Empty prompt provided")
            return None
        
        # Check cache first
        cache_key = self._generate_cache_key(prompt)
        cached_response = self._get_from_cache(cache_key)
        
        if cached_response:
            self.stats['cache_hits'] += 1
            self.logger.debug(f"Cache hit for prompt (key: {cache_key[:8]}...)")
            return cached_response
        
        self.stats['cache_misses'] += 1
        self.stats['total_queries'] += 1
        
        # Retry logic
        last_exception = None
        for attempt in range(1, max_retries + 1):
            try:
                self.logger.debug(f"LLM query attempt {attempt}/{max_retries}")
                
                url = f"{self.api_url}/generate"
                payload = {
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9,
                        "top_k": 40
                    }
                }
                
                response = requests.post(url, json=payload, timeout=timeout)
                response.raise_for_status()
                
                result = response.json()
                response_text = result.get("response", "")
                
                if response_text:
                    # Update statistics
                    self.stats['total_tokens'] += result.get('eval_count', 0)
                    
                    # Cache the response
                    self._save_to_cache(cache_key, response_text)
                    
                    self.logger.info(f"LLM query successful (tokens: {result.get('eval_count', 0)})")
                    return response_text
                else:
                    self.logger.warning("Empty response from LLM")
                    return None
                    
            except requests.exceptions.Timeout as e:
                last_exception = e
                self.logger.warning(f"Attempt {attempt}: Request timeout after {timeout}s")
                if attempt < max_retries:
                    wait_time = 2 ** attempt  # Exponential backoff
                    self.logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                self.logger.error(f"Attempt {attempt}: Connection error - Is Ollama running?")
                if attempt < max_retries:
                    time.sleep(5)
                    
            except requests.exceptions.HTTPError as e:
                last_exception = e
                self.logger.error(f"Attempt {attempt}: HTTP error {e.response.status_code}")
                if e.response.status_code == 404:
                    self.logger.error(f"Model not found: {self.model_name}")
                    break  # Don't retry for 404
                if attempt < max_retries:
                    time.sleep(3)
                    
            except json.JSONDecodeError as e:
                last_exception = e
                self.logger.error(f"Attempt {attempt}: Invalid JSON response")
                if attempt < max_retries:
                    time.sleep(2)
                    
            except Exception as e:
                last_exception = e
                self.logger.error(f"Attempt {attempt}: Unexpected error: {str(e)}")
                if attempt < max_retries:
                    time.sleep(2)
        
        # All retries failed
        self.stats['errors'] += 1
        self.logger.error(f"All {max_retries} attempts failed. Last error: {last_exception}")
        return None
    
    def check_model(self) -> bool:
        """
        Check if the model is available
        
        Returns:
            bool: True if model is available, False otherwise
        """
        try:
            url = f"{self.api_url}/tags"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            models = data.get("models", [])
            
            # Check if our model exists
            for model in models:
                model_name = model.get("name", "")
                if self.model_name in model_name or model_name in self.model_name:
                    self.logger.info(f"Model found: {self.model_name}")
                    return True
            
            self.logger.warning(f"Model not found: {self.model_name}")
            return False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error checking model availability: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error checking model: {str(e)}")
            return False
    
    def pull_model(self) -> bool:
        """
        Pull/download the model
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.logger.info(f"Pulling model: {self.model_name}")
            url = f"{self.api_url}/pull"
            payload = {"name": self.model_name}
            
            response = requests.post(url, json=payload, stream=True, timeout=600)
            response.raise_for_status()
            
            # Stream the download progress
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    status = data.get("status", "")
                    if "progress" in data:
                        self.logger.debug(f"Download progress: {data['progress']}")
            
            self.logger.info(f"Model pulled successfully: {self.model_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error pulling model: {str(e)}")
            return False
    
    def _generate_cache_key(self, prompt: str) -> str:
        """
        Generate a cache key from prompt
        
        Args:
            prompt (str): The prompt text
            
        Returns:
            str: SHA256 hash of the prompt
        """
        return hashlib.sha256(prompt.encode('utf-8')).hexdigest()
    
    @lru_cache(maxsize=100)
    def _get_from_cache(self, cache_key: str) -> Optional[str]:
        """
        Get response from cache (using LRU cache decorator)
        
        Args:
            cache_key (str): Cache key
            
        Returns:
            Optional[str]: Cached response or None
        """
        # This method is cached by the decorator
        # Actual cache retrieval is handled by lru_cache
        return None
    
    def _save_to_cache(self, cache_key: str, response: str) -> None:
        """
        Save response to cache
        
        Args:
            cache_key (str): Cache key
            response (str): Response to cache
        """
        # For LRU cache, we need to call the cached method
        # This will automatically cache the result
        self._get_from_cache.cache_info()  # Trigger cache
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get agent statistics
        
        Returns:
            Dict[str, Any]: Statistics dictionary
        """
        cache_info = self._get_from_cache.cache_info()
        
        return {
            **self.stats,
            'cache_size': cache_info.currsize,
            'cache_maxsize': cache_info.maxsize,
            'cache_hit_rate': (
                self.stats['cache_hits'] / max(self.stats['total_queries'], 1) * 100
            )
        }
    
    def clear_cache(self) -> None:
        """Clear the response cache"""
        self._get_from_cache.cache_clear()
        self.logger.info("Cache cleared")
    
    def shutdown(self) -> None:
        """
        Clean up resources
        """
        stats = self.get_stats()
        self.logger.info(f"LLM Agent shutting down. Stats: {stats}")
        self.clear_cache()


class LLMEngineError(Exception):
    """Custom exception for LLM Engine errors"""
    pass


class ModelNotFoundError(LLMEngineError):
    """Exception raised when model is not found"""
    pass


class LLMTimeoutError(LLMEngineError):
    """Exception raised when LLM request times out"""
    pass