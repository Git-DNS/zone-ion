# A tiny zone-format note for people browsing this repository.
#
# Full documentation lives in the GitDNS source repository:
# docs/ZONE_FORMAT.md.
#
# This folder contains one directory per registered name. The apex is
# domains/_records.toml. A name a.b uses domains/a/b/_records.toml. Every
# non-apex file needs an ed25519 signature from its owner. The browser site and
# scripts/zone_admin.py both create and verify the canonical payload described
# in the root README.
