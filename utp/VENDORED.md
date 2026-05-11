# libutp — vendored from upstream

This directory contains a verbatim copy of [BitTorrent's libutp](https://github.com/bittorrent/libutp), the reference implementation of micro Transport Protocol (uTP / BEP-29).

## Source

- Upstream repository: <https://github.com/bittorrent/libutp>
- Vendored at commit: `2b364cbb0650bdab64a5de2abb4518f9f228ec44`
- Vendored on: 2026-05-11
- Vendored for: amule-project NAT-T + uTP feature (see `.archive/eMuleAI-nat-t-implementation-plan.md` for context)

## License

[MIT](LICENSE) © 2010-2013 BitTorrent, Inc. Compatible with aMule's GPLv2+ license.

## What changed locally

Nothing yet — initial vendor is bit-identical to upstream `2b364cbb`.

If we need patches in future, they go here as numbered notes, e.g.:

> **patch 1 (TBD)**: backport upstream commit `<sha>` for `<reason>`.

Always prefer fixing in this directory rather than embedding aMule-specific code into libutp.

## Why vendored (not submoduled, not packaged dep)

- Downstream packagers don't have to install a `libutp-dev` package — relevant for `apt` / `brew` / MSYS2 maintainers.
- Build reproducibility: the version aMule builds against is fixed in-tree.
- libutp upstream is essentially unmaintained (last upstream commit predates 2020); vendoring a known-good revision protects against the library disappearing.

## Refreshing from upstream

To re-vendor a newer revision:

```sh
TMP=$(mktemp -d)
git clone --depth 1 https://github.com/bittorrent/libutp.git "$TMP/libutp"
NEW_SHA=$(git -C "$TMP/libutp" rev-parse HEAD)

# Replace .cpp/.h, keep VENDORED.md
cp "$TMP/libutp"/*.cpp "$TMP/libutp"/*.h utp/
cp "$TMP/libutp/LICENSE" utp/LICENSE
cp "$TMP/libutp/README.md" utp/README-upstream.md

# Bump the SHA + date in this file's "Vendored at commit" line.
```

Then audit the diff for any local patches that need re-applying.
