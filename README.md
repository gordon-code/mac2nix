# mac2nix

Generate nix-darwin configurations from macOS system scans.

## Install

```sh
uv sync
```

## Usage

```sh
uv run mac2nix --help
```

### Migrating a Mac

Scaffold a reusable, host-less nix-darwin + home-manager + sops-nix framework,
register a machine, scan it, and generate that host's configuration:

```sh
uv run mac2nix init ~/my-nix-config
uv run mac2nix add-host ~/my-nix-config --hostname my-mac --username myuser
uv run mac2nix generate ~/my-nix-config --hostname my-mac
```

`init` runs once per framework (it scaffolds `flake.nix`, shared `modules/`,
and sops-nix wiring with zero hosts registered). `add-host` registers one
machine at a time — including the first — generating that host's own
sops-nix age key behind a mandatory backup-confirmation prompt. `generate`
scans the current machine (or replays a `mac2nix scan` JSON file via
`--scan-file`) and writes that host's curated `preferences.nix`, updating
`configuration.nix`'s generated-imports section. It's safely re-runnable and
supports `--domains` to select which domains to generate (currently just
`preferences`; more are added incrementally).

## License

MIT
