# Changelog

## 1.5.1 - 2026-11-27

- Raise the configurable native-path streaming chunk ceiling to 128 MiB.
- Allocate file-copy buffers with fallible reservation and expose a stable `memoryAllocation` error kind.
- Map allocation failures from the core streaming hasher to the same stable client error kind.
- Add streaming-buffer initialization coverage.

