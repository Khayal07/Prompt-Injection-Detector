# Prompt Injection & Jailbreak Detector

🚧 Work in progress.

A real-time firewall layer for LLM applications — detects prompt injection attempts, jailbreak patterns, and manipulation before they reach the model.

## Idea

Most LLM apps trust raw user input as-is. This service adds a detection layer in front of the model that scores incoming prompts for risk (instruction overrides, role-play jailbreaks, delimiter/encoding attacks, system-prompt extraction attempts) and blocks or flags the malicious ones.

## Planned Architecture

- **Heuristic layer** — fast, config-driven pattern matching for known jailbreak structures
- **Classifier layer** — handles ambiguous cases the heuristics miss
- **FastAPI service** — `/check` endpoint any LLM app can call before forwarding input to the model
- **Postgres logging** — every request/verdict stored for later evaluation
- **Eval suite** — precision/recall/latency benchmarks against a labeled dataset

## Tech Stack

- Python, FastAPI
- PostgreSQL
- Docker / docker-compose

## Status

Currently building out the core detection layer. Setup instructions, API docs, and eval results will be added as the project progresses.

## License

MIT