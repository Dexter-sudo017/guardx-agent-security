# SRTP Strict Benchmark Suite

- Created: `2026-05-10T15:45:36`
- Cases: `114`
- Risky: `71`
- Benign: `43`
- Policy: safe abstractions only; no raw harmful prompt payloads are stored.

## Splits

| split | cases | risky | benign |
| --- | ---: | ---: | ---: |
| train | 74 | 44 | 30 |
| dev | 22 | 16 | 6 |
| test | 10 | 8 | 2 |
| heldout | 8 | 3 | 5 |

## Families

| family | cases |
| --- | ---: |
| AdvBench | 5 |
| Benign Lookalike | 20 |
| GCG / llm-attacks | 7 |
| HarmBench | 5 |
| Indirect Prompt Injection | 13 |
| JailbreakBench | 14 |
| Multimodal Prompt Injection | 11 |
| RAG Benign Lookalike | 5 |
| SRTP EmbedGuard Stress | 24 |
| XSTest | 10 |

## Use

Use `split=train` for risk-head fitting, `split=dev` for threshold calibration, and `split=test` for final claims.
