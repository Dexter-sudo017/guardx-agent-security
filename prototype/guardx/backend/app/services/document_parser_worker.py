from __future__ import annotations

import base64
import contextlib
import json
import sys

from app.services.document_ingestion import parse_document_bytes, release_document_parser


def main() -> int:
    try:
        request = json.load(sys.stdin)
        parsed = []
        with contextlib.redirect_stdout(sys.stderr):
            for item in request.get("files") or []:
                parsed.append(
                    parse_document_bytes(
                        filename=str(item.get("filename") or "uploaded-file"),
                        content=base64.b64decode(str(item.get("content_base64") or ""), validate=True),
                    )
                )
            release_document_parser()
        response = {"documents": parsed}
    except Exception as exc:
        response = {"error": f"{type(exc).__name__}: {exc}"}
    json.dump(response, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
