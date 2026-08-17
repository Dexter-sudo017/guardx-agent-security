from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Callable, TypeVar


T = TypeVar("T")


class PhaseTimedOut(TimeoutError):
    pass


def call_with_timeout(action: Callable[[], T], *, timeout_ms: float, phase: str) -> T:
    if timeout_ms <= 0:
        return action()
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(action)
    try:
        result = future.result(timeout=timeout_ms / 1000.0)
    except FutureTimeout as exc:
        future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise PhaseTimedOut(f"{phase} timed out after {timeout_ms:.0f}ms") from exc
    except Exception:
        executor.shutdown(wait=True)
        raise
    executor.shutdown(wait=True)
    return result
