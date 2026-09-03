#!/usr/bin/env bash
set -euo pipefail

forbidden='lenso-platform-|lenso-module-auth|HostBuilder|HostLinkedModule|ModuleManifest|lenso module install|platform_core|platform_module'

if rg -n "$forbidden" Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo "legacy Lenso framework dependency or API found in Access Request source" >&2
  exit 1
fi

if rg -n 'CREATE TABLE (users|sessions|organizations|memberships|roles|permissions|role_bindings|grants)' \
  crates/lenso-access-request-postgres-plugin/migrations; then
  echo "Access Request crossed Auth, Organization, or Access Control storage ownership" >&2
  exit 1
fi

if rg -n '(println!|eprintln!|dbg!|tracing::[a-z]+!)\([^\n]*(recipient|lease_token|database_url|assertion)' \
  crates/lenso-access-request-postgres-plugin/src --glob '!postgres_tests.rs'; then
  echo "sensitive Access Request material reached a diagnostic macro" >&2
  exit 1
fi

if rg -n '(html|template|reason|decision_note):' \
  crates/lenso-access-request-postgres-plugin/src/lib.rs | rg 'CreateAccessRequestNotification'; then
  echo "unbounded content crossed the Access Request Notification Port" >&2
  exit 1
fi

test -f crates/lenso-access-request-requester-agent-tools-plugin/src/lib.rs
test -f crates/lenso-access-request-admin-agent-tools-plugin/src/lib.rs
rg -q 'lenso-capability-agent-tool-provider' Cargo.toml

if ! rg -q 'status=.unknown.*automatic_retry_allowed=FALSE|status=\x27unknown\x27,revision=revision\+1,automatic_retry_allowed=FALSE' \
  crates/lenso-access-request-postgres-plugin/src/storage.rs; then
  echo "unknown Access Control effects are not visibly terminal for automatic retry" >&2
  exit 1
fi

printf 'repository boundary is access-request-only, authority-separated, and vNext-only\n'
