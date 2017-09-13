__version__ = '0.2.2'

from datetime import datetime

import logging
import os
import time

def set_stream_logger(name="iraas", level=logging.INFO,
                      format_string=None):

    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    time_format = "%Y-%m-%dT%H:%M:%S"

    logger = logging.getLogger(name)
    logger.setLevel(level)
    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(level)
    streamFormatter = logging.Formatter(format_string, time_format)
    streamHandler.setFormatter(streamFormatter)
    logger.addHandler(streamHandler)
