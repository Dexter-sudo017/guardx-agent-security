# GuardX Unified External Benchmarks

This directory defines the unified metadata layer for external benchmark evaluation.

The unified suite is intentionally split into three evidence levels:

1. `external_raw_hash_local`: local private/raw benchmark rows used only for evaluation runs. Public reports render hashes and aggregates, not high-risk raw prompts.
2. `official_safe_abstraction`: metadata-only or safe abstraction cases derived from official benchmark threat models. These are not leaderboard scores.
3. `source_inspired_safe_abstraction`: probes inspired by common red-team tools such as Promptfoo, garak, and PyRIT. They cover missing surfaces such as terminal output, repository prompt injection, and OCR hidden instruction.

The loader writes runnable JSONL artifacts under `data/external_benchmarks/`, which is ignored by git. Tracked reports must not render raw high-risk prompts.
