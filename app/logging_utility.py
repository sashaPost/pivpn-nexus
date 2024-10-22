import logging
import os
from logging.handlers import RotatingFileHandler


class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._setup_logger()
        return cls._instance

    def _setup_logger(self):
        self.logger = logging.getLogger('VPNNexusManager')
        self.logger.setLevel(logging.INFO)

        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, 'vpn_nexus_manager.log')

        # Use RotatingFileHandler to limit log file size
        file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024,
                                           backupCount=3)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(pathname)s - %(message)s')
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)

    def get_logger(self):
        return self.logger


logger = Logger().get_logger()