# Changelog

## 1.6.0 - 2026-11-28

- Align the Rust client crate and `majik-signature` dependency at 1.6.0.
- Add native-path `sign_batch_detached_paths_stream()` using format-aware canonical readers and the core streaming batch API.
- Add trusted-key `verify_mjks_map_paths_stream()` using the core streaming MJKSMAP verifier.
- Expose batch progress, per-file byte limits, cancellation, and failure-continuation settings.
- Preserve both MJKSMAP and separate MJKSIG batch output modes.
- Align native chunk overrides at 64 MiB maximum to match the core 1.6.0 limit.
- Add preflight bounds for batch count, normalized manifest paths, and MIME metadata before opening any native sources.
- Add adversarial tests for traversal/control characters, normalized duplicate paths, overlong metadata, and oversized batch lists.
- Document public streaming fields/helpers and crate-level modules, correct the TypeScript package link, and add the repository security policy.
- Add tests for multi-file canonical reader preparation and supported chunk boundaries.


## 1.5.1 - 2026-11-27

- Raise the configurable native-path streaming chunk ceiling to 128 MiB.
- Allocate file-copy buffers with fallible reservation and expose a stable `memoryAllocation` error kind.
- Map allocation failures from the core streaming hasher to the same stable client error kind.
- Add streaming-buffer initialization coverage.

