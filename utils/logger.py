# utils/logger.py
import logging
import os
from datetime import datetime

def setup_logger(log_level=logging.INFO):
    """Loglama yapılandırmasını kurar."""
    
    # Logs klasörü yoksa oluştur
    if not os.path.exists('logs'):
        os.makedirs('logs')

    log_filename = datetime.now().strftime('logs/agent_%Y-%m-%d.log')

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger("CyberSecAgent")