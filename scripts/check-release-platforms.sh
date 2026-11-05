#!/usr/bin/env bash
# Verifies that a release image index contains every promised platform.
#
# Reads the space/newline separated output of:
#   docker buildx imagetools inspect <image>@<digest> \
#     --format '{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}}{{with .Platform.Variant}}/{{.}}{{end}} {{end}}'
#
# OCI/BuildKit normally reports 64-bit ARM images as `linux/arm64/v8`, while
# other builders omit the implicit variant and report `linux/arm64`. Both
# spellings satisfy the release's `linux/arm64` requirement; other variants
# (for example `linux/arm64/v9`) do not. Attestation manifests appear as
# `unknown/unknown` and are ignored by the explicit allowlist.
set -euo pipefail

readonly -a REQUIRED_PLATFORMS=(linux/amd64 linux/arm64 linux/arm/v7)

normalize_platform() {
    case "$1" in
        linux/arm64/v8) printf '%s\n' "linux/arm64" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

declare -a observed=()
while IFS= read -r token; do
    [ -n "${token}" ] || continue
    observed+=("$(normalize_platform "${token}")")
done < <(tr ' ' '\n')

missing=0
for expected in "${REQUIRED_PLATFORMS[@]}"; do
    found=0
    for platform in "${observed[@]}"; do
        if [ "${platform}" = "${expected}" ]; then
            found=1
            break
        fi
    done
    if [ "${found}" -eq 0 ]; then
        echo "::error::image index is missing required platform ${expected}" >&2
        missing=1
    fi
done

printf 'platforms: %s\n' "${observed[*]:-<none>}"
if [ "${missing}" -ne 0 ]; then
    exit 1
fi
