# Working on this repo with Claude Code

Project conventions live in [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
local workflow in [`docs/development.md`](docs/development.md). Read those
first — this file only covers things specific to working here with an agent.

## Commits

- Follow [Conventional Commits](https://www.conventionalcommits.org/), as
  `CONTRIBUTING.md` describes: `<type>: <summary>`, body explaining why.
- **Do not add `Co-Authored-By: Claude` or any other agent attribution
  trailer**, and don't mention Claude or Claude Code in commit messages.
  The commit author is the person running the tool.
- The same goes for pull request descriptions: no "generated with" footer.
- Prefer several small, structured commits over one large one when a change
  has distinct parts.

## Before you call something done

```sh
uv run ruff check . && uv run ruff format --check .
uv run pytest -q
```

Both have to pass. If a test fails, say so with the output rather than
describing the change as finished.
