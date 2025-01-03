import os
import logging
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
from queue import Queue

class LoggerConfig:
    _instance = None  # 单例模式的实例变量

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(LoggerConfig, cls).__new__(cls)
        return cls._instance

    def __init__(self, log_file='./log/mininet.log', level=logging.DEBUG, mode='w', max_bytes=5*1024*1024, backup_count=3):
        self.log_file = log_file
        self.level = level
        self.mode = mode
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.ryu_level = logging.WARNING
        self.queue = Queue()  # 日志队列
        self._ensure_log_directory_exists()
        self._setup_logging()

    def _ensure_log_directory_exists(self):
        """Ensure the directory for the log file exists."""
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

    def _setup_logging(self):
        # 获取根 logger
        logger = logging.getLogger()
        logger.setLevel(self.level)

        # 移除所有现有的处理器
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

        # 创建日志队列处理器
        queue_handler = QueueHandler(self.queue)
        logger.addHandler(queue_handler)

        # 创建文件处理器
        file_handler = RotatingFileHandler(self.log_file, mode='w', maxBytes=self.max_bytes, backupCount=self.backup_count)
        file_handler.setLevel(self.level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.level)
        console_handler.setFormatter(formatter)

        # 启动日志队列监听器
        self.listener = QueueListener(self.queue, file_handler, console_handler)
        self.listener.start()

        # 单独设置 Ryu 模块的日志级别
        ryu_logger = logging.getLogger("ryu")
        ryu_logger.setLevel(self.ryu_level)
        ryu_logger.propagate = False  # 防止日志传播到根 logger

        controller_logger = logging.getLogger("controller")
        controller_logger.setLevel(self.ryu_level)
        controller_logger.propagate = False

    @classmethod
    def get_logger(cls, name=__name__):
        # 确保配置只初始化一次
        if not cls._instance:
            cls()  # 初始化单例实例

        # 使用给定的名字获取 logger
        return logging.getLogger(name)

    def stop_listener(self):
        """停止日志队列监听器"""
        if hasattr(self, 'listener'):
            self.listener.stop()
