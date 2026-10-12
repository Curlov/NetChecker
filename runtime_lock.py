"""Cooperative process coordination without stopping the scanner process."""
from contextlib import contextmanager
from functools import wraps
import fcntl
import os
import sys
import threading
from runtime_config import DATABASE_PATH

_held = threading.local()


class InventoryBusy(RuntimeError):
    """Another cooperating writer owns this inventory."""


@contextmanager
def inventory_lock(nonblocking=False, database_path=None):
    from pathlib import Path
    path = Path(database_path or DATABASE_PATH).resolve().with_suffix('.lock')
    key = (os.getpid(), str(path.resolve()))
    locks = getattr(_held, 'locks', {})
    if key in locks:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError as error:
            raise InventoryBusy('Inventory writer is busy') from error
        locks[key] = handle
        _held.locks = locks
        try:
            yield
        finally:
            locks.pop(key, None)
            fcntl.flock(handle, fcntl.LOCK_UN)


def exclusive_cycle(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with inventory_lock():
            return function(*args, **kwargs)
    return wrapped


def coordinated_entry(function):
    """Scheduled work postpones itself; explicitly invoked work waits."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            with inventory_lock(nonblocking='--try-lock' in sys.argv):
                return function(*args, **kwargs)
        except InventoryBusy:
            return 75
    return wrapped


def single_scanner(function):
    """Own a separate lifetime lock before initializing or recovering runs."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        path = DATABASE_PATH.with_suffix('.scanner.lock')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InventoryBusy('A scanner is already running for this database')
            try:
                return function(*args, **kwargs)
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    return wrapped
