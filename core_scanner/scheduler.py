"""Bounded ThreadPoolExecutor orchestration with cooperative cancellation."""
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from .config import MAX_IN_FLIGHT_FACTOR, COMPLETION_POLL_INTERVAL
from .models import ScanCancelled, ScanExecutionError, _check_cancelled

def scan_ports_bounded(ports, worker, workers, cancel_event=None, max_in_flight=None):
    """Execute a bounded window of futures and retain exact port/result mapping.

    No more than max_in_flight tasks are submitted and unfinished at any time
    (running + queued), including on Python versions where Executor.map()
    eagerly consumes its input. Pending futures are cancelled on interruption.
    All running tasks are joined so that sockets/threads are not abandoned.
    """
    if not 1 <= workers <= 100:
        raise ValueError("workers must be between 1 and 100")
    limit = max_in_flight if max_in_flight is not None else workers * MAX_IN_FLIGHT_FACTOR
    if type(limit) is not int or not workers <= limit <= workers * MAX_IN_FLIGHT_FACTOR:
        raise ValueError("max_in_flight must be between workers and 2 * workers")
    cancel_event = cancel_event if cancel_event is not None else threading.Event()
    _check_cancelled(cancel_event)
    iterator = iter(ports)
    pending = {}
    results = {}
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        exhausted = False
        while not exhausted or pending:
            _check_cancelled(cancel_event)
            while not exhausted and len(pending) < limit:
                _check_cancelled(cancel_event)
                try:
                    port = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                future = executor.submit(worker, port)
                pending[future] = port
            if not pending:
                break
            completed, _ = wait(pending, timeout=COMPLETION_POLL_INTERVAL,
                                return_when=FIRST_COMPLETED)
            _check_cancelled(cancel_event)
            for future in completed:
                port = pending.pop(future)
                try:
                    results[port] = future.result()
                except ScanCancelled:
                    cancel_event.set()
                    raise
                except Exception as exc:
                    cancel_event.set()
                    raise ScanExecutionError(
                        "worker failed; scan results are incomplete"
                    ) from exc
        _check_cancelled(cancel_event)
        return results
    except BaseException:
        cancel_event.set()
        for future in pending:
            future.cancel()
        raise
    finally:
        # Explicit future cancellation works on Python 3.8 as well.
        executor.shutdown(wait=True)
