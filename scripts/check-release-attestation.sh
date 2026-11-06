#!/usr/bin/env bash
# Verify that a BuildKit attestation JSON payload contains a given attestation
# type (for example "SLSA" provenance or "SPDX" SBOM).
#
# Reads the JSON from stdin and consumes it completely.  This matters under
# `set -o pipefail`: the previous inline `printf ... | grep -q` check could
# make the producer die with SIGPIPE when grep exited early, turning a present
# attestation into a false negative after the image had already been pushed.
#
# Usage: check-release-attestation.sh NEEDLE
set -euo pipefail

needle=${1:?usage: check-release-attestation.sh NEEDLE}
payload="$(cat)"

if [[ "${payload}" != *"\"${needle}\""* ]]; then
  echo "missing \"${needle}\" attestation" >&2
  exit 1
fi
