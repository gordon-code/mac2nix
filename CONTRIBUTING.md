# Contributing to mac2nix

## Commit Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <description>
```

### Types

| Type       | Description                          |
|------------|--------------------------------------|
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `refactor` | Code change (no new feature or fix)  |
| `docs`     | Documentation only                   |
| `build`    | Build system or dependencies         |
| `ci`       | CI configuration                     |
| `test`     | Adding or updating tests             |
| `perf`     | Performance improvement              |
| `chore`    | Maintenance tasks                    |

### Scopes

| Scope        | Description                        |
|--------------|------------------------------------|
| `cli`        | CLI commands and options           |
| `scanners`   | macOS system scanners              |
| `generators` | Nix configuration generators       |
| `mappings`   | macOS-to-nix mapping tables        |
| `models`     | Data models                        |
| `reports`    | Scan reports and diffs             |
| `templates`  | Jinja2 nix templates               |
| `vm`         | Tart VM integration                |
| `drift`      | Configuration drift detection      |
| `deps`       | Dependency updates                 |
| `ci`         | CI/CD pipeline                     |

### Examples

```
feat(scanners): add homebrew formula scanner
fix(cli): correct exit code on scan failure
docs(models): add SystemState field descriptions
test(generators): add nix module output tests
```

## Development

```sh
uv sync                # install dependencies
uv run pytest          # run tests
uv run ruff check src/ tests/    # lint
uv run ruff format src/ tests/   # format
uv run pyright         # type check
```
