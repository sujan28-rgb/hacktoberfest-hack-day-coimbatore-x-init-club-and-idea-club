# Sentinel Evidence case viewer

The React/TypeScript frontend consumes the case-scoped FastAPI application.
See the [root README](../README.md) for backend and frontend setup. From this directory,
run `npm ci`, then `npm run dev -- --host 127.0.0.1`.

Open http://127.0.0.1:5173, create a case, and import a documented JSONL file.
The viewer shows deterministic findings/claims, source records, complete packets
and the optional validated local explanation or fallback.

`npm run build` checks TypeScript and produces the production bundle.
`npm run lint` runs Oxlint.
