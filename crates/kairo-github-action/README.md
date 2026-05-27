# Kairo GitHub Action

A GitHub Action that runs Kairo risk checks on pull requests.

## Overview

The `kairo/check` action analyzes pull request changes to detect risky actions such as:
- Package manager lockfile changes (npm, pnpm, yarn, bun, pip, cargo)
- CI/CD workflow modifications
- Dockerfile changes
- Database migrations (Prisma)
- Infrastructure as Code changes
- Environment file modifications

## Usage

```yaml
name: Kairo Check
on: [pull_request]

jobs:
  kairo-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Kairo Check
        uses: your-org/kairo-github-action@main
        with:
          policy: moderate
          github-token: ${{ secrets.GITHUB_TOKEN }}
          api-url: http://your-kairo-server:8080
          fail-on: block
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `policy` | Policy level: `strict`, `moderate`, or `permissive` | No | `moderate` |
| `github-token` | GitHub token for posting comments and status checks | Yes | `${{ github.token }}` |
| `api-url` | Kairo Decision Server URL | No | `http://127.0.0.1:8080` |
| `fail-on` | Fail on: `block`, `warn`, or `allow` | No | `block` |

## Outputs

The action posts:
1. A PR comment with detailed risk analysis
2. A commit status check (`success`, `warning`, or `error`)

## Fail-on Modes

- `block`: Fail only if BLOCK verdicts are found
- `warn`: Fail if any WARN or BLOCK verdicts are found
- `allow`: Never fail based on verdicts

## Example

```yaml
uses: your-org/kairo-github-action@main
with:
  policy: moderate
  github-token: ${{ secrets.GITHUB_TOKEN }}
  api-url: http://kairo-server:8080
  fail-on: warn
```

## Local Development

Build the Docker image:
```bash
docker build -t kairo-github-action .
```

Run locally (simulating GitHub Actions environment):
```bash
docker run -e GITHUB_EVENT_NAME=pull_request \
           -e GITHUB_EVENT_PATH=./event.json \
           -e GITHUB_WORKSPACE=/workspace \
           -e GITHUB_REPOSITORY=owner/repo \
           kairo-github-action moderate <token> http://localhost:8080 block
```
