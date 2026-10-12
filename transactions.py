"""Nested transactions never commit writes owned by their caller."""
from contextlib import contextmanager
from itertools import count

_savepoints = count()


@contextmanager
def atomic(connection):
    nested = connection.in_transaction
    name = f'netchecker_{next(_savepoints)}'
    connection.execute(f'SAVEPOINT {name}' if nested else 'BEGIN')
    try:
        yield
    except BaseException:
        if nested:
            connection.execute(f'ROLLBACK TO {name}')
            connection.execute(f'RELEASE {name}')
        else:
            connection.rollback()
        raise
    else:
        if nested:
            connection.execute(f'RELEASE {name}')
        else:
            connection.commit()
