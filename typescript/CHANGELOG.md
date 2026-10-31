# Changelog

All notable changes to `@pogly/spacetimedb-webhooks` are listed here. It follows [semantic versioning](https://semver.org/).

## Unreleased

## 0.1.4 (2026-10-31)

- A crash can no longer strand a delivery. A flush job is deleted before the flush runs, so a crash with a delivery in flight used to leave the message waiting for the next event. A backstop job is now committed with the lease, and the message is redelivered when the lease ends.

## 0.1.3 (2026-10-30)

- Works with SpacetimeDB 2.14: the `spacetimedb` peer range is now `2.13.* || 2.14.*`. A module built with the 2.14 library needs a 2.14 or newer host.
- Outbound delivery uses `ctx.http.fetch`. The `rawPost` workaround is gone, because the SDK keeps `webhook-signature: v1,...` intact since 2.13, so 2.13 is now the minimum.
- `package.json` declares `submodule.category` for the [SpacetimeDB submodule registry](https://spacetimedb.com/submodules).

## 0.1.2 (2026-10-13)

- Works with SpacetimeDB 2.12: the `spacetimedb` peer range is now `2.11.* || 2.12.*`. No code changes.

## 0.1.1 (2026-10-10)

- First release published from CI through npm trusted publishing, with provenance. No code changes.

## 0.1.0 (2026-10-10)

- First release on npm.
