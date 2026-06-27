# patchwork-demo-billing

A tiny billing service used to demo **Patchwork**. It intentionally depends on
`lodash.set@4.3.2`, which is affected by **GHSA-p6mc-m468-83gw** (prototype
pollution) with **no patched release** — a version bump cannot fix it.
Patchwork writes a real code-level guard instead.
