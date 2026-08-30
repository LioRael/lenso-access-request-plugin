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

checkout_exact_repository() {
  local environment_variable="$1"
  local repository_url="$2"
  local revision="$3"
  local checkout_name="$4"
  local configured="${!environment_variable:-}"
  local checkout

  if [[ -n "$configured" ]]; then
    checkout="$(git -C "$configured" rev-parse --show-toplevel)"
  else
    checkout="$verification_root/$checkout_name"
    git clone --quiet --filter=blob:none --no-checkout "$repository_url" "$checkout"
    git -C "$checkout" checkout --quiet --detach "$revision"
  fi

  local actual_revision
  actual_revision="$(git -C "$checkout" rev-parse HEAD)"
  if [[ "$actual_revision" != "$revision" ]]; then
    printf '%s must resolve to %s, got %s\n' \
      "$environment_variable" "$revision" "$actual_revision" >&2
    return 1
  fi
  printf '%s\n' "$checkout"
}

access_control_root="$(checkout_exact_repository \
  LENSO_ACCESS_CONTROL_REPOSITORY \
  https://github.com/LioRael/lenso-access-control-plugin \
  de1e1f1ec61232b13fc90a05f1cb4e3fc96ba420 \
  access-control)"
notification_root="$(checkout_exact_repository \
  LENSO_NOTIFICATION_REPOSITORY \
  https://github.com/LioRael/lenso-notification-plugin \
  b001dffea970789858499efa2049853d37bc3e0f \
  notification)"
organization_root="$(checkout_exact_repository \
  LENSO_ORGANIZATION_REPOSITORY \
  https://github.com/LioRael/lenso-organization-plugin \
  9572afd465ba2f952b646ec16935c0274f66c82a \
  organization)"
secrets_root="$(checkout_exact_repository \
  LENSO_SECRETS_REPOSITORY \
  https://github.com/LioRael/lenso-secrets-plugin \
  c31aa142ff59b4536e2bf3e9785ccbb5bb5c0e6a \
  secrets)"

external_names=(
  lenso-capability-access-control
  lenso-capability-access-control-admin
  lenso-capability-notification-transactional
  lenso-capability-organization-directory
  lenso-capability-organization-membership
  lenso-capability-secrets
)
external_expected_versions=(
  0.1.0
  0.1.0
  0.1.0
  0.1.0
  0.1.0
  0.1.1
)
external_roots=(
  "$access_control_root"
  "$access_control_root"
  "$notification_root"
  "$organization_root"
  "$organization_root"
  "$secrets_root"
)
external_sources=(
  "$access_control_root/crates/lenso-capability-access-control"
  "$access_control_root/crates/lenso-capability-access-control-admin"
  "$notification_root/crates/lenso-capability-notification-transactional"
  "$organization_root/crates/lenso-capability-organization-directory"
  "$organization_root/crates/lenso-capability-organization-membership"
  "$secrets_root/crates/lenso-capability-secrets"
)
external_versions=()
external_archives=()

for index in "${!external_names[@]}"; do
  name="${external_names[$index]}"
  root="${external_roots[$index]}"
  dependency_metadata="$($cargo_bin metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version=1)"
  dependency_target="$(jq -r '.target_directory' <<<"$dependency_metadata")"
  version="$(jq -r --arg name "$name" '.packages[] | select(.name == $name) | .version' <<<"$dependency_metadata")"
  expected_version="${external_expected_versions[$index]}"
  if [[ "$version" != "$expected_version" ]]; then
    printf '%s must package as %s, got %s\n' "$name" "$expected_version" "$version" >&2
    exit 1
  fi
  "$cargo_bin" package --quiet --locked --manifest-path "$root/Cargo.toml" -p "$name"
  external_versions+=("$version")
  external_archives+=("$dependency_target/package/$name-$version.crate")
done

source_patches=()
for capability in "${capabilities[@]}"; do
  source_patches+=(--config "patch.crates-io.${capability}.path=\"${repository_root}/crates/${capability}\"")
done
for index in "${!external_names[@]}"; do
  source_patches+=(--config "patch.crates-io.${external_names[$index]}.path=\"${external_sources[$index]}\"")
done

# Archive creation needs source patches because the exact Capability revisions
# may not be published yet. The extracted, normalized consumer graph is fully
# checked, tested, and linted below.
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

for index in "${!external_names[@]}"; do
  name="${external_names[$index]}"
  version="${external_versions[$index]}"
  tar -xzf "${external_archives[$index]}" -C "$verification_root"
  package="$verification_root/${name}-${version}"
  [[ -f "$package/Cargo.toml" ]]
  archive_patches+=(--config "patch.crates-io.${name}.path=\"${package}\"")
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
