"""Game-thread finder: the thread named 'GameThread', else the process's earliest-created thread."""
import logging
from typing import TYPE_CHECKING, NamedTuple

from ..errors import DetectionError

if TYPE_CHECKING:
    from ...process.thread import Thread

logger = logging.getLogger('nylib.ue.runtime.gamethread')

GAME_THREAD_NAME = 'GameThread'
THREAD_QUERY_LIMITED = 0x0800  # THREAD_QUERY_LIMITED_INFORMATION


class GameThreadId(NamedTuple):
    thread_id: int
    method: str  # 'description' | 'earliest'


def find_game_thread_id(process, *, mem=None) -> GameThreadId:
    """The game thread's id in `process` (the target, or current_process() when injected); DetectionError if no signal yields one.

    `mem` is reserved for memory-based signals and unused. A thread that cannot be queried is skipped."""
    named, earliest = [], None  # earliest = (creation_time, tid)
    try:
        for t in process.iter_threads(da=THREAD_QUERY_LIMITED):
            with t:
                try:
                    created, description = t.creation_time(), t.description()
                except OSError:
                    continue
            if description == GAME_THREAD_NAME:
                named.append(t.thread_id)
            if earliest is None or created < earliest[0]:
                earliest = created, t.thread_id
    except OSError as err:
        raise DetectionError('game thread', f'cannot scan the threads of process {process.process_id}: {err}') from err
    first = earliest[1] if earliest is not None else None
    if len(named) == 1:
        if first != named[0]:
            logger.warning('game thread: the thread named %r is %d but the earliest thread is %s; using the named thread',
                           GAME_THREAD_NAME, named[0], first)
        return GameThreadId(named[0], 'description')
    if len(named) > 1:
        logger.warning('game thread: %d threads are named %r (%s); falling back to the earliest thread', len(named), GAME_THREAD_NAME, named)
    if first is None:
        raise DetectionError('game thread', f'no queryable thread in process {process.process_id}')
    return GameThreadId(first, 'earliest')


def open_game_thread(process, *, mem=None, da: int = THREAD_QUERY_LIMITED) -> 'Thread':
    """Open the thread find_game_thread_id names; the caller owns it.

    Raises DetectionError when no thread qualifies, the thread exited before the open, or the open is refused."""
    tid = find_game_thread_id(process, mem=mem).thread_id
    try:
        return process.get_thread(tid, da=da)
    except ValueError as exc:
        raise DetectionError('game thread', f'thread {tid} of process {process.process_id} exited before it could be opened: {exc}') from exc
    except OSError as exc:
        if getattr(exc, 'winerror', None) == 87:  # ERROR_INVALID_PARAMETER: no such thread
            raise DetectionError('game thread', f'thread {tid} of process {process.process_id} exited before it could be opened: {exc}') from exc
        raise DetectionError('game thread', f'cannot open thread {tid} of process {process.process_id} with access {da:#x}: {exc}') from exc
