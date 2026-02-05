# Infra

A shared set of infrastructure to used across the Policy Radar estate.

We aim to
[pave Golden Paths](https://www.pulumi.com/blog/golden-paths-infrastructure-components-and-templates/).

## What Makes a Golden Path Golden?

Drawing from Spotify’s pioneering work, golden paths share these
characteristics:

- _Pre-architected and Supported:_ The platform team owns and supports the path
- _Optional but Recommended:_ Developers can deviate, but staying on the path
  ensures support
- _Transparent Abstractions:_ The implementation is visible, not a black box
- _Extensible:_ Teams can add project-specific resources without breaking the
  pattern
- _Evolutionary:_ Templates improve based on feedback and new requirements

## Release

Releases are handled by
[release-please](https://github.com/googleapis/release-please) via the
[release-please-action](https://github.com/googleapis/release-please-action) in
[release.yml](.github/workflows/release.yml).
