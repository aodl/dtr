# DTR working rules

This repository owns only the reusable deterministic timeline runtime. It must not depend on Balls 2 The Wallz or encode game-specific physics, pricing, payment memos, rendering or deployment configuration.

- Preserve canonical public encodings, seals, publication v6 and recovery behavior.
- Keep competitive Life as the independent generic-boundary example.
- Use Rust 1.94.1, Node 22.16 or newer, committed lockfiles and locked Cargo commands.
- Run `npm test` and `cargo test --workspace --locked` for behavioral changes; also run format and Clippy before finishing.
- Never inspect or commit identity files, PEM files, wallet keys, seed phrases or environment secrets.
- Do not deploy to a public network, publish packages, push remotes or change repository visibility without explicit authorization.
- Keep changes small and avoid gameplay, cryptography, scheduler, storage or plugin frameworks.
