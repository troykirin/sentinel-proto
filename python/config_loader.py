"""Configuration loader for Sentinel."""

import sys
from pathlib import Path

# tomllib landed in Python 3.11; fall back to tomli for older versions
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        raise ImportError(
            "Python < 3.11 requires the 'tomli' package. "
            "Install it with: pip install tomli"
        )

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / 'config' / 'sentinel_config.toml'


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    """Load TOML configuration from the given path.

    Raises FileNotFoundError if the path does not exist.
    Raises tomllib.TOMLDecodeError on malformed TOML.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, 'rb') as f:
        return tomllib.load(f)
