# Workflow checker

![tests](https://github.com/twistedsol/workflow-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads GitHub Actions workflow files (`.github/workflows/*.yml`) and flags risky settings. It reads the text line by line. It never runs a workflow or contacts GitHub. Standard library only, no installs.

## Run it

```
python workflow_checker.py sample_workflows/01_risky.yml
python workflow_checker.py sample_workflows/*.yml
python workflow_checker.py .github/workflows/tests.yml
python workflow_checker.py sample_workflows/01_risky.yml --format json
```

On Windows I use `py -3.13` instead of `python`. The last text command checks this repo's own workflow, and you can point it at the workflows in any of your repos.

Three sample workflows are included. They are made up for practice:

| File | What it is | Findings |
|---|---|---|
| `01_risky.yml` | A badly written workflow | 11 (5 high) |
| `02_okay_with_gaps.yml` | Looks fine but leaves gaps (it is close to my own test workflows) | 4 (0 high) |
| `03_hardened.yml` | A hardened workflow | 0 |

Every finding shows the **line number**.

## What it checks

| Rule | Severity | Flags |
|---|---|---|
| permissions-write-all | high | `permissions: write-all` |
| script-injection | high | Text from an issue, comment, pull request or branch name pasted into a `run:` command |
| pr-target-checkout | high | Checking out pull request code in a `pull_request_target` workflow |
| curl-pipe-shell | high | Downloading a script and running it straight away |
| action-branch-ref | high | An action pinned to `@main`, `@master`, `@latest` and similar |
| pull-request-target | medium | The `pull_request_target` trigger |
| no-permissions | medium | No `permissions:` block anywhere |
| self-hosted-runner | medium | `runs-on: self-hosted` |
| secret-in-run | medium | `${{ secrets.X }}` written directly in a command |
| input-in-run | medium | A workflow input pasted into a command |
| action-not-pinned | low | An action on a tag (such as `@v4`) or a Docker image without a digest |
| checkout-keeps-token | low | `actions/checkout` without `persist-credentials: false` |

## Options

- `--format text|json` (default text)
- `--min-severity low|medium|high` hides findings below that level
- `--fail-on low|medium|high` sets which level makes the exit code 1 (default high)

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` bad input (missing or unreadable file).

## Test it

```
python -m unittest -v
```

51 tests cover how `run:` blocks are found, each rule and its edges, bad input, the command line and the sample files. GitHub Actions runs them on Python 3.10 and 3.12. The workflow also checks its own file and must find no high findings.

## How I built it

I used AI to help write the code and tests, then ran everything myself, read each rule and checked the sample results by hand. The rules follow public GitHub Actions security advice.

## Limits

- It reads lines, not real YAML. Unusual layouts, anchors or very odd formatting can be missed or misread.
- It only looks at `run:` text for injection. Other places that run code, such as `actions/github-script`, are not checked.
- It does not look inside reusable workflows or the actions you call.
- Pinning to a SHA is the strongest choice, but it is a trade-off with easy updates, so tags are only a low finding.
- It cannot know whether a repository is public or private, which changes how risky self-hosted runners are.

## Next ideas

- Read real YAML if I allow one extra library
- Check `docker-compose.yml` files too
- Add a score out of 100
