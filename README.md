# SentinelMesh

Security Incident Intelligence & Attack Investigation Platform

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

## Local Docker foundation

The repository includes a reproducible local Docker foundation with:

- a Next.js frontend on port `3000`
- a MySQL 8.0 service with the named `sentinelmesh_mysql_data` volume
- a Python initialization container that runs the existing
	`src.storage.incident_store` database initializer

The repository does not currently expose a Python HTTP API. The `backend`
Compose service therefore initializes the existing SentinelMesh tables and
exits successfully; it is not an API server. No application persistence or
frontend integration with MySQL is enabled by this foundation.

Create a local `.env` from `.env.example`, then start the stack with:

```bash
docker compose up --build
```

The MySQL service is available to the Python container as `mysql`, never as
`localhost`. Ollama/Qwen remains an external local provider and is not
containerized by this milestone. The Linux Python image intentionally omits
`pywin32`, which is required only by the Windows event-log ingestor.
