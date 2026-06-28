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
