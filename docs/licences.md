# Third-party models and data

Checked 2026-10-04 against the Hugging Face model cards (licence field) at the pinned revisions.

| Item | Use | Licence | Source / revision |
|---|---|---|---|
| Qwen3.8-27B-FP8 | local chat for confidential work, L2 judge | Apache-2.0 | `Qwen/Qwen3.8-27B-FP8` @ 017b9c7a |
| Bielik-11B-v3.0-Instruct-FP8-Dynamic | local Polish legal specialist | Apache-2.0 | `speakleash/Bielik-11B-v3.0-Instruct-FP8-Dynamic` @ cfa5e0e7 |
| Qwen3-Embedding-0.6B | local embeddings (Insights, similarity) | Apache-2.0 | `Qwen/Qwen3-Embedding-0.6B` @ 97b0c614 |
| DeBERTa-v3 prompt-injection v2 (ONNX) | SEC-PI-01 classifier | Apache-2.0 | `protectai/deberta-v3-base-prompt-injection-v2` @ 90c9989b |
| GLiNER multi-PII v1 (ONNX int8) | SEC-NER-01 | Apache-2.0 (base `urchade/gliner_multi_pii-v1`) | `onnx-community/gliner_multi_pii-v1` @ 2e0397a7 |
| Gemini Flash / Pro | cloud models (public/internal data only) | Google API terms | API, no weights |
| vLLM 0.29 (apptainer image) | serving on WCSS | Apache-2.0 | `vllm/vllm-openai:v0.29.0` |

Weights are never committed; they are fetched into a cache outside the repo (WCSS HF cache, `%USERPROFILE%\.cache\rogatka-models`)
with sha256 recorded.
