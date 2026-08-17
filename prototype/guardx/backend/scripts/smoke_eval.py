from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.eval_suite import run_smoke_suite
from app.main import app

def main() -> int:
    suite = run_smoke_suite(app)
    for result in suite["results"]:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"{status} {result['name']}: {result['detail']}")
    print(f"summary: {suite['passed']}/{suite['total']} passed")
    return 0 if suite["passed"] == suite["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
