"""Structured local event logs; credentials and device payloads are not logged."""
import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler


class EventFormatter(logging.Formatter):
    def format(self, record):
        payload = {'time':datetime.now(timezone.utc).isoformat(), 'level':record.levelname,
                   'event':record.getMessage(), 'module':record.name}
        payload.update(getattr(record, 'event_data', {}))
        if record.exc_info:
            payload['exception_type'] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False)


def configure_logging():
    logger = logging.getLogger('netchecker')
    if logger.handlers:
        return logger
    path = os.environ.get('NETCHECKER_LOG_FILE')
    handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=5, encoding='utf-8') if path else logging.StreamHandler()
    handler.setFormatter(EventFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def event(name, **data):
    configure_logging().info(name, extra={'event_data':data})
