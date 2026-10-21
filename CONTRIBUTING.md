# Contributing

Create focused changes with tests. Network tests must use local fakes and may
not contact public systems. Before submitting a change, run:

```bash
ruff check .
ruff format --check .
mypy src
pytest
```

Changes to version boundaries must cite an official PHP or distribution advisory.
