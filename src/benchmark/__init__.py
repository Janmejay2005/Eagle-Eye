"""
Benchmark package for Eagle-Eye.
Uses lazy attribute loading to prevent runpy circular execution warnings when invoked with -m.
"""

def __getattr__(name):
    if name in ("BenchmarkRunner", "run_benchmark_and_save_reports"):
        from src.benchmark.benchmark_runner import BenchmarkRunner, run_benchmark_and_save_reports
        return {
            "BenchmarkRunner": BenchmarkRunner,
            "run_benchmark_and_save_reports": run_benchmark_and_save_reports,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["BenchmarkRunner", "run_benchmark_and_save_reports"]
