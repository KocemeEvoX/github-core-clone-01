# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/kocemeevox/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/kocemeevox/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single Node.js file: git clone/push over smart HTTP, REST v3, GraphQL, and MCP, with no dependencies beyond the Node standard library.

## Run it

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:8080 node --experimental-strip-types main.ts
```

The forge is one standalone process. It binds an ephemeral port, registers it with the make.fun harness at `MAKEFUN_ENV_URL`, and serves all four surfaces until the harness says the trial is done:

- **Git smart HTTP** — protocol v2 (`ls-refs`, `fetch` with shallow/deepen, `receive-pack` with report-status), plus v0 advertisement and fetch. SHA-1 object store with plain packfiles, sideband-64k, fast-forward and mixed-push handling.
- **REST v3** — repositories, branches, commits, contents, labels, issues, comments, and pull requests with squash merge, under `/api/v3`.
- **GraphQL** — the queries and mutations `gh` and github-mcp-server send, with Relay-style global ids and cursor pagination.
- **MCP** — JSON-RPC tools for creating and reading repos, issues, and pull requests.

Everything is in `app.ts` (Node 22 standard library only: `node:http`, `node:crypto`, `node:zlib`). `main.ts` is the harness lifecycle: bind, register, poll `/done`, exit 0. No git binary, no package manager, no network access at trial time, and no wall-clock state — timestamps are deterministic, so a replayed trial produces byte-identical results.

## Local check

The kit's local grader runs the sealed conformance suite against a running forge:

```sh
node --experimental-strip-types sdk/run.ts --url http://127.0.0.1:PORT --token test-token --perf
```

On the practice instances this entry scores **120/120 conformance checks** (git 30, repos 15, issues 15, pulls 20, GraphQL 20, MCP 15, protocol 5) for a local score of **973** (600 feature + 200 agent + 173 perf).

---

<sub>Entered on [make.fun](https://make.fun/?ref=mwzsh35h&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
