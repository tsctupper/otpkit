"""Compare two Git trees using the scanner installed beside this trusted script."""

import json
import sys
from pathlib import Path

# CI extracts both modules into its own temporary directory before starting Python in isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dependency_inventory import compare, scan_repo

FIRST_PARTY = {
    "@tsctupper/otpkit": {
        "repository": "tsctupper/otpkit",
        "version": "1.1.3",
        "gitHead": "71c4efeaa38878a015efe86b02f441864aeea8c5",
        "integrity": "sha512-iAG66UihNs4RvNgjp49n5e6QFyxmDyLRouuezWs9KW8RCtx0jPheWNOdxZfgyobDI4exIdjXrRZ3dLndCPxQ6A=="
    }
}


def main():
    repository, base_sha, candidate_sha = sys.argv[1:]
    try:
        baseline, candidate = [
            scan_repo(".", sha, repository, "maintainer", first_party_packages=FIRST_PARTY)
            for sha in (base_sha, candidate_sha)
        ]
        result = compare(baseline, candidate)
        retained_packages = {
            item["name"] for item in candidate["dependencies"] if item["ecosystem"] == "npm"
        }
        lost_proof = (
            baseline.get("first_party_provenance", {}).keys()
            - candidate.get("first_party_provenance", {}).keys()
        )
        if lost_proof & retained_packages:
            result.update(
                state="first_party_provenance_changed",
                exit_code=2,
                packages_requiring_review=sorted(lost_proof & retained_packages),
            )
        result["candidate_counts"] = candidate["category_counts"]
        result["base_counts"] = baseline["category_counts"]
        result["npm_units"] = candidate.get("npm_units")
        result["provenance"] = "UNKNOWN"
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        result = {"state": "unknown", "reason": str(error), "exit_code": 3}
    print(json.dumps(result, indent=2))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
