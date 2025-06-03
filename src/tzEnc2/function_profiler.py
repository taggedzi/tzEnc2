import time
import threading
from functools import wraps
from collections import defaultdict

class FunctionProfiler:
    """Tracks call counts, total time, and average execution time for decorated functions."""
    _lock = threading.Lock()
    _stats = defaultdict(lambda: {'count': 0, 'total_time': 0.0})

    @classmethod
    def track(cls, name=None):
        """Decorator to track function execution time and count."""
        def decorator(func):
            label = name or func.__qualname__

            @wraps(func)
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                result = func(*args, **kwargs)
                duration = time.perf_counter() - start

                with cls._lock:
                    data = cls._stats[label]
                    data['count'] += 1
                    data['total_time'] += duration

                return result
            return wrapper
        return decorator

    @classmethod
    def report(cls, top_n=None):
        """Return a summary of all tracked functions sorted by total time."""
        with cls._lock:
            items = [
                (label, data['count'], data['total_time'], data['total_time'] / data['count'] if data['count'] else 0)
                for label, data in cls._stats.items()
            ]
            # Sort by total time descending
            items.sort(key=lambda x: x[2], reverse=True)

        lines = ["Function Profile Summary:"]
        lines.append(f"{'Function':<40} {'Calls':>8} {'Total Time':>12} {'Avg Time':>12}")
        lines.append("-" * 75)

        for label, count, total, avg in items[:top_n or len(items)]:
            lines.append(f"{label:<40} {count:>8} {total:>12.6f} {avg:>12.6f}")

        return "\n".join(lines)

    @classmethod
    def reset(cls):
        """Reset the collected statistics."""
        with cls._lock:
            cls._stats.clear()
