#!/usr/bin/env bash
# Regression test for the release attestation gate.
#
# The old inline `printf ... | grep -q` check failed when the payload was
# large enough for grep to exit before printf finished: pipefail turned the
# SIGPIPE into a false negative after the image had already been published.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check="${root}/scripts/check-release-attestation.sh"
tmp=$(mktemp)
trap 'rm -f "${tmp}"' EXIT

# A representative, large multi-platform payload with both attestations.
python3 - "${tmp}" <<'PY'
import json
import sys

padding = "x" * 500_000
payload = {
    "linux/amd64": {"SLSA": {"buildDefinition": padding}, "SPDX": {"SPDXID": "SPDXRef-DOCUMENT"}},
    "linux/arm64": {"SLSA": {"buildDefinition": padding}, "SPDX": {"SPDXID": "SPDXRef-DOCUMENT"}},
    "linux/arm/v7": {"SLSA": {"buildDefinition": padding}, "SPDX": {"SPDXID": "SPDXRef-DOCUMENT"}},
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY

# Both checks must succeed and the producer must be able to write the full
# payload under pipefail (the old implementation produced SIGPIPE here).
set -o pipefail
printf '%s' "$(cat "${tmp}")" | "${check}" SLSA
printf '%s' "$(cat "${tmp}")" | "${check}" SPDX

# A missing attestation must still fail closed.
if printf '%s' "$(cat "${tmp}")" | "${check}" MISSING; then
  echo "expected a missing-attestation failure" >&2
  exit 1
fi

echo "release attestation gate test OK"
