"""utils/logger.py"""
import logging, sys

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"netphantom.{name}")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(h)
    logger.setLevel(logging.WARNING)
    return logger
