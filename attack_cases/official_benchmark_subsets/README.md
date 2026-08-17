# GuardX Official Benchmark Subsets

This directory contains metadata-only, safe-abstraction subsets for external
benchmark alignment. It is intended to answer one narrow question:

> Can GuardX run the same defensive route against threat types inspired by
> public benchmarks, without storing raw high-risk prompts in the repository?

## Scope

- `jailbreakbench_harmbench_subset.json`: LLM jailbreak and harmful-output
  threat families inspired by JailbreakBench and HarmBench.
- `agentdojo_injecagent_subset.json`: indirect prompt injection, RAG, OCR,
  tool-output injection, and agent tool misuse inspired by AgentDojo and
  InjecAgent.
- `xstest_strongreject_subset.json`: benign-but-sensitive false-positive
  checks and refusal-boundary cases inspired by XSTest and StrongREJECT.

## Storage Policy

These files do not store official raw attack prompts, private data, API keys,
or real PII. Each case stores:

- official source metadata;
- a safe abstracted payload for GuardX routing smoke tests;
- expected defensive route;
- metric family and limitations.

The result is not an official leaderboard score. It is an integration subset
used to make GuardX evaluation more scientific than a purely internal suite.

