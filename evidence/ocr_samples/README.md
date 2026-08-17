# GuardX OCR Evidence Fixtures

These files are synthetic evidence fixtures for the `guardx_source_inspired_probe` OCR/VLM cases. They are designed to support competition replay and Portal evidence without storing real personal information.

## Scope

- `source-docvqa-style-hidden-margin-001.svg`: document-style image with a visible audit paragraph and a low-contrast margin instruction.
- `source-cord-style-receipt-001.svg`: receipt-style image with synthetic fields and an injected privacy exfiltration note.
- `source-funsd-style-form-001.svg`: benign form-style image with a privacy notice.

## Reproducibility Rules

- All images are synthetic SVG fixtures created in this repository.
- OCR text files under `ocr_text/` are deterministic fixture transcriptions for tests and demos.
- `manifest.json` records image hashes, OCR output hashes, bounding boxes for hidden text, synthetic/PII flags, and the matching experiment case IDs.
- `real_ocr_manifest.json` records actual Tesseract and PaddleOCR runs over Edge-rendered PNGs, including engine version, languages or runtime package versions, input image hash, and output hash.
- Any later PaddleOCR or Tesseract run should append a new manifest entry instead of overwriting these fixture hashes.

## Real OCR Capture

The current committed real OCR evidence was generated with:

- Renderer: Microsoft Edge headless `148.0.3967.96`
- OCR engine: Tesseract `v5.4.0.20240606`
- Languages: `chi_sim+eng`
- OCR engine: PaddleOCR `3.6.0` with PaddlePaddle `3.2.2`
- Tessdata policy: local ignored cache under `data/ocr_tools/tessdata/`
- PaddleOCR model cache policy: local ignored cache under the user's PaddleX model cache.

Re-run command:

```powershell
cd F:\srtp\信安赛
.\prototype\guardx\backend\.venv\Scripts\python.exe .\prototype\guardx\backend\scripts\run_ocr_evidence_capture.py --engines tesseract
```

To refresh both OCR engines:

```powershell
cd F:\srtp\信安赛
.\prototype\guardx\backend\.venv\Scripts\python.exe .\prototype\guardx\backend\scripts\run_ocr_evidence_capture.py --engines tesseract,paddleocr
```

Do not commit `.venv` or model/tool caches.

## Privacy Rules

- `contains_real_pii` must remain `false`.
- Fake values such as `13800000000` and `TEST-20260602` are test markers only.
- Decoder or OCR replay reports should store hashes and aggregate metrics by default.
