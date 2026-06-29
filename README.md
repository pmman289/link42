# Link42

Link42 is a lightweight internal WireGuard node and link management panel.

The first version focuses on:

- Adding managed nodes.
- Running a Python agent on each node.
- Managing point-to-point WireGuard link configs.
- Importing existing `wg-quick` configs.
- Previewing and confirming changes before agent deployment.

See [docs/architecture.md](docs/architecture.md) for the guiding architecture.

## Development

Install Python dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

Run the API:

```bash
uvicorn link42_api.main:app --app-dir apps/api --reload
```

Run tests:

```bash
pytest
```

## Project Structure

See [docs/project-structure.md](docs/project-structure.md) for the repository layout.

## Controller Docker Image

Build the controller image:

```bash
scripts/controller/build-image.sh
```

Build and push it to DockerHub:

```bash
scripts/controller/push-image.sh tagname
```

Export the image for another machine:

```bash
scripts/controller/export-image.sh
```

On the target machine, pull and run it:

```bash
docker pull pmman/link42:tagname
docker run -d --name link42-controller -p 8000:8000 -v /opt/link42:/link42 pmman/link42:tagname
```

Or import an exported tar:

```bash
docker load -i link42-controller-latest.tar
docker run -d --name link42-controller -p 8000:8000 -v /opt/link42:/link42 pmman/link42:latest
```

Run with Docker Compose:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

The container listens on port `8000` and serves both the API and the web panel.
Runtime files live under one parent directory inside the container:

- `/link42/data` stores the SQLite database.
- `/link42/config` is reserved for config files and future overrides.

For a host bind mount, map one parent directory to `/link42`.
