"""Only CLEAN permits deployment."""

import argparse
import json

from mcp_authscan.policy_check import evaluate


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("policy")
    parser.add_argument("keys")
    parser.add_argument("--challenge-db")
    parser.add_argument("--deployment-id")
    args = parser.parse_args(argv)

    try:
        registry_options = {}

        if args.challenge_db is not None:
            registry_options["challenge_db"] = args.challenge_db

        if args.deployment_id is not None:
            registry_options["deployment_id"] = args.deployment_id

        result = evaluate(
            args.report,
            args.policy,
            args.keys,
            **registry_options,
        )
        code = {"CLEAN": 0, "CONDITIONAL": 2}.get(
            result.get("verdict"), 1
        )
    except Exception as exc:
        result = {
            "verdict": "REJECT",
            "check": "GATE-ERROR",
            "detail": type(exc).__name__,
        }
        code = 1

    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
