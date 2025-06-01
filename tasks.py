import os
import shutil
import sys
import platform
from invoke import task
use_pty = platform.system() != "Windows"


# ---- Config ----
PYTHON = sys.executable
VENV_DIR = "venv"
SRC_DIR = "src"
TEST_DIR = "tests"
DIST_DIR = "dist"
DOCS_DIR = "docs"

use_pty = platform.system() != "Windows"

@task
def clean(c):
    """Clean up build, dist, cache, and pyc files."""
    patterns = [DIST_DIR, "*.egg-info", ".pytest_cache", ".mypy_cache", "__pycache__", ".coverage", ".venv", ".tox"]
    for pattern in patterns:
        c.run(f"rm -rf {pattern}", warn=True)
    print("✔ Cleaned project.")


@task
def lint(c):
    """Run linting tools (flake8 and black)."""
    c.run("flake8 src/ tests/", warn=True)
    c.run("black --check src/ tests/", warn=True)
    print("✔ Lint checks complete.")


@task
def format(c):
    """Autoformat the code with black."""
    c.run("black src/ tests/")
    print("✔ Code formatted.")


@task
def test(c):
    """Run tests using pytest."""
    c.run("pytest tests/", pty=use_pty)
    print("✔ Tests executed.")


@task
def build(c):
    """Build the package."""
    c.run("python -m build", pty=use_pty)
    print("✔ Build complete.")


@task
def install(c):
    """Install the package locally."""
    c.run("pip install -e .", pty=use_pty)
    print("✔ Package installed locally.")


@task
def docs(c):
    """Build Sphinx documentation (if applicable)."""
    c.run(f"sphinx-build {DOCS_DIR} {DOCS_DIR}/_build", warn=True)
    print("✔ Documentation built.")


@task
def release(c):
    """Clean, build, and upload the package."""
    clean(c)
    build(c)
    print("🚀 Ready to upload to PyPI or TestPyPI.")


@task(default=True)
def all(c):
    """Run all major tasks."""
    lint(c)
    test(c)
    build(c)
