#!/usr/bin/env python3
"""Turn a govulncheck JSON stream into a build verdict.

The build fails on a finding that is both reachable and actionable:

  reachable   govulncheck traced a call into the vulnerable symbol, rather
              than merely finding the module in the graph. A trace of one
              frame is a module- or package-level match; anything deeper is a
              real call path out of this code.

  actionable  the advisory names a fixed version. An advisory with no fix
              cannot be acted on, and failing every build on it teaches the
              team to ignore the scanner — which is the outcome that actually
              costs something. Those are printed instead, and the day a fix is
              published the same rule starts enforcing it, with no list of
              exceptions to remember to prune.

Reads the JSON stream on stdin. Exits non-zero when the build should fail.
"""

import json
import sys


def findings(raw):
    """Yield the finding objects from govulncheck's stream of JSON documents."""
    decoder = json.JSONDecoder()
    i = 0
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            return
        obj, i = decoder.raw_decode(raw, i)
        if "finding" in obj:
            yield obj["finding"]


def main():
    raw = sys.stdin.read()
    try:
        found = list(findings(raw))
    except ValueError as err:
        print(f"::error::could not parse govulncheck output: {err}")
        return 1

    blocking, unfixed = {}, {}
    for finding in found:
        osv = finding.get("osv")
        fixed = finding.get("fixed_version")
        # One frame means the module was found, not that anything calls it.
        called = len(finding.get("trace") or []) > 1
        if not called:
            continue
        if fixed:
            blocking[osv] = fixed
        else:
            unfixed[osv] = True

    for osv in sorted(unfixed):
        print(f"::warning::{osv} is reachable and has no fix available; "
              f"see https://pkg.go.dev/vuln/{osv}")

    for osv, fixed in sorted(blocking.items()):
        print(f"::error::{osv} is reachable and fixed in {fixed}; "
              f"upgrade the dependency — https://pkg.go.dev/vuln/{osv}")

    if blocking:
        return 1
    print(f"vulnerability gate: clear ({len(unfixed)} reachable without a fix, none actionable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
