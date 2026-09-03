#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-access-request-packages.XXXXXX")"
package_flags=(--locked)
plugin_flags=()

cleanup() {
  if [[ "${LENSO_KEEP_PACKAGE_TMP:-0}" == "1" ]]; then
    printf 'kept package verification root: %s\n' "$verification_root" >&2
  else
    rm -r "$verification_root"
  fi
}
trap cleanup EXIT

if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
  plugin_flags+=(--allow-dirty)
fi

capabilities=(
  lenso-capability-access-request-requester
  lenso-capability-access-request-admin
  lenso-capability-access-request-worker
)

for capability in "${capabilities[@]}"; do
  "$cargo_bin" package --quiet "${package_flags[@]}" -p "$capability"
done

metadata="$($cargo_bin metadata --no-deps --format-version=1)"
target_directory="$(jq -r '.target_directory' <<<"$metadata")"
plugin_version="$(jq -r '.packages[] | select(.name == "lenso-access-request-postgres-plugin") | .version' <<<"$metadata")"

for adapter in \
  lenso-access-request-requester-agent-tools-plugin \
  lenso-access-request-admin-agent-tools-plugin; do
  publish="$(jq -r --arg adapter "$adapter" '.packages[] | select(.name == $adapter) | .publish | length' <<<"$metadata")"
  if [[ "$publish" != "0" ]]; then
    printf '%s must remain private\n' "$adapter" >&2
    exit 1
  fi
done

source_patches=()
for capability in "${capabilities[@]}"; do
  source_patches+=(--config "patch.crates-io.${capability}.path=\"${repository_root}/crates/${capability}\"")
done
# Archive creation needs source patches only for this repository's unpublished
# Capability packages. Released external dependencies resolve from crates.io.
"$cargo_bin" "${source_patches[@]}" package --quiet "${plugin_flags[@]}" --no-verify \
  -p lenso-access-request-postgres-plugin

archive_patches=()
for capability in "${capabilities[@]}"; do
  version="$(jq -r --arg name "$capability" '.packages[] | select(.name == $name) | .version' <<<"$metadata")"
  archive="$target_directory/package/${capability}-${version}.crate"
  tar -xzf "$archive" -C "$verification_root"
  package="$verification_root/${capability}-${version}"
  [[ -f "$package/Cargo.toml" ]]
  archive_patches+=(--config "patch.crates-io.${capability}.path=\"${package}\"")
done

plugin_archive="$target_directory/package/lenso-access-request-postgres-plugin-${plugin_version}.crate"
tar -xzf "$plugin_archive" -C "$verification_root"
plugin_package="$verification_root/lenso-access-request-postgres-plugin-${plugin_version}"
plugin_manifest="$plugin_package/Cargo.toml"
[[ -f "$plugin_manifest" ]]
[[ -f "$plugin_package/configuration.schema.json" ]]
[[ -f "$plugin_package/migrations/001_create_access_request_workflow.sql" ]]

"$cargo_bin" "${archive_patches[@]}" generate-lockfile --manifest-path "$plugin_manifest"
"$cargo_bin" "${archive_patches[@]}" check --quiet --locked --all-targets --manifest-path "$plugin_manifest"
"$cargo_bin" "${archive_patches[@]}" test --quiet --locked --manifest-path "$plugin_manifest"
"$cargo_bin" clippy "${archive_patches[@]}" --quiet --locked --all-targets \
  --manifest-path "$plugin_manifest" -- -D warnings
