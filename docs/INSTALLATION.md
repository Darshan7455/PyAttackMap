# Installation Guide

PyAttackMap requires Python 3.11 or newer.

## Standard Installation

To install the distribution release via pip:

```bash
python -m pip install pyattackmap
```

## Local Development Installation

To install PyAttackMap for local development and testing:

```bash
git clone https://github.com/pyattackmap/pyattackmap.git
cd pyattackmap

# Install in editable mode with development dependencies (pytest)
python -m pip install -e ".[dev]"
```

## Verifying the Installation

Check the installed version and command-line entry point:

```bash
python -c "import pyattackmap as pam; print(pam.__version__)"
pyattackmap --version
pyattackmap --help
```

## Running the Test Suite

Execute the test suite using pytest:

```bash
python -m pytest tests/ -v
```

