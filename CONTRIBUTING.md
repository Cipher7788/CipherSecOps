# Contributing to CipherSecOps

Thank you for your interest in contributing! This document explains how to get
involved and what standards we expect.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Branch Naming](#branch-naming)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## Getting Started

1. **Fork** the repository on GitHub and **clone** your fork locally:

   ```bash
   git clone https://github.com/<your-username>/CipherSecOps.git
   cd CipherSecOps
   git remote add upstream https://github.com/Cipher7788/CipherSecOps.git
   ```

2. **Create a virtual environment** and install the server and agent dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate          # Windows: .venv\Scripts\activate
   pip install -r server/requirements.txt
   pip install -r agent/requirements.txt
   pip install flake8 mypy pytest pytest-asyncio pytest-cov httpx
   ```

3. **Install dashboard dependencies**:

   ```bash
   cd dashboard && npm ci && cd ..
   ```

4. **Copy the example environment file** and fill in the required values:

   ```bash
   cp .env.example .env
   ```

5. **Start the full stack** with Docker Compose:

   ```bash
   docker compose up -d
   ```

---

## Branch Naming

Use a short, descriptive branch name with one of the following prefixes:

| Prefix   | Use for                                      |
|----------|----------------------------------------------|
| `feature/` | New functionality                          |
| `fix/`     | Bug fixes                                  |
| `docs/`    | Documentation-only changes                 |
| `chore/`   | Dependency updates, CI tweaks, refactoring |
| `test/`    | Adding or improving tests only             |

Examples: `feature/kafka-alert-streaming`, `fix/agent-memory-leak`, `docs/api-reference`

Always branch off `main`:

```bash
git fetch upstream
git checkout -b feature/my-feature upstream/main
```

---

## Code Standards

### Python (server & agent)

- **Style**: Follow [PEP 8](https://peps.python.org/pep-0008/). Maximum line length is **100 characters**.
- **Linting**: All code must pass `flake8` with no errors:
  ```bash
  flake8 server/ agent/ --max-line-length=100
  ```
- **Type hints**: Every public function and method must have type annotations.
- **Type checking**: Code must pass `mypy` without errors:
  ```bash
  mypy server/ agent/ --ignore-missing-imports
  ```
- **Docstrings**: Use [Google-style docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for all public modules, classes, and functions.
- **Imports**: Group imports as standard library → third-party → local, separated by blank lines.

### TypeScript / JavaScript (dashboard)

- Follow the existing ESLint and Prettier configuration.
- Use functional React components and hooks; avoid class components.
- Keep component files focused — one component per file.

### General

- Do not leave debug `print()` or `console.log()` statements in production code.
- Prefer explicit over implicit; avoid magic numbers and unexplained constants.
- Keep commits small and focused. Each commit should represent one logical change.

---

## Testing Requirements

- **All new features** must include accompanying tests.
- **Bug fixes** must include a regression test that reproduces the bug.
- Tests must pass locally before opening a PR:

  ```bash
  # Server tests (requires running Postgres & Redis)
  pytest tests/ --ignore=tests/test_agent -v

  # Agent tests
  pytest tests/test_agent/ -v

  # Dashboard
  cd dashboard && npm test -- --watchAll=false
  ```

- Aim to maintain or improve the existing code coverage percentage.
- Use `pytest-asyncio` for async server endpoints and `httpx.AsyncClient` for
  integration tests.

---

## Pull Request Process

1. **Keep your branch up to date** with `upstream/main` before opening a PR:

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run the full CI suite locally** (lint + tests + dashboard build) and fix any failures.

3. **Open a Pull Request** against the `main` branch with:
   - A clear title that summarises the change.
   - A description explaining *what* changed and *why*.
   - Reference to any related issues (e.g. `Closes #42`).

4. **Address review feedback** promptly. Discussions should be resolved before merging.

5. PRs require **at least one approving review** before merge. The CI pipeline must be green.

6. Squash or rebase commits if requested by a reviewer to keep the history clean.

---

## Reporting Issues

Please use [GitHub Issues](https://github.com/Cipher7788/CipherSecOps/issues) to report bugs or request features. Include:

- A clear description of the problem or proposal.
- Steps to reproduce (for bugs).
- Expected and actual behaviour.
- Relevant logs, screenshots, or configuration snippets.

For security vulnerabilities, **do not** open a public issue. Contact the
maintainers privately via the GitHub security advisory feature.
