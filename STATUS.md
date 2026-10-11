# Current status — S11 extraction

The reusable DTR sources have been extracted from `aodl/placeholder` revision `7ff33b8573e7191deb6a3b23f748bb988ccc280f`. The tested implementation is local commit `71e59e93cf49a3656689679b538b4c3f138787f8` on `checkpoint/s11-dtr-extraction`.

Standalone Rust, JavaScript, Life, formatting, Clippy, package-inventory and immutable-artifact clean-consumer checks pass. The BTZ application consumes this exact Rust revision and the corresponding npm-pack artifact; its full baseline-upgrade and live certified-observer scenario also passes locally.

Remote clean-clone and fresh CI remain **BLOCKED** until an authorized `https://github.com/aodl/dtr.git` remote is created and this local history is pushed. No registry publication, package release or public-network deployment occurred.
