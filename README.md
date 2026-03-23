# IPv11-S OpenCLAW Implementation (`code`)

This folder contains the runnable implementation of the IPv11-S concept from
`../ipv11_social_position_paper.md`.

## Components

- `openclaw_demo.py`: Python FastAPI control-plane demo (API server).
- `cpp/src/ipv11s_openclaw.cpp`: C++ concept implementation (CLI simulation).
- `Dockerfile.openclaw`: Docker image for the Python API.
- `Dockerfile.cpp`: Docker image for the C++ simulation executable.
- `docker-compose.openclaw.yml`: Docker Compose for the Python API demo.

## Python API (Docker)

Build:

```bash
docker build -f Dockerfile.openclaw -t ipv11-openclaw-demo:latest .
```

Run:

```bash
docker run --rm -p 8011:8011 ipv11-openclaw-demo:latest
```

Smoke test:

```bash
curl -X POST http://localhost:8011/api/v1/demo/bootstrap
curl -X POST http://localhost:8011/api/v1/interactions/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "src_agent_id":"agent-alpha",
    "dst_agent_id":"agent-beta",
    "action":"critical-transfer-execute",
    "mode":"hybrid",
    "auth_token":"DA-SIGNED::hospital-net::agent-alpha"
  }'
```

## C++ Simulation (Docker)

Build:

```bash
docker build -f Dockerfile.cpp -t ipv11s-openclaw-cpp:latest .
```

Run:

```bash
docker run --rm ipv11s-openclaw-cpp:latest
```

The C++ output prints allow/deny decisions using:
- Stage A reachability checks
- Stage B legitimacy checks (scope, trust threshold, culture profile)
- Hybrid centralized token checks (`DA-SIGNED::<domain>::<agent_id>`)
