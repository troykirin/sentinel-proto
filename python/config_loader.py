"""Configuration loader for Sentinel."""

from pathlib import Path
import tomllib

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
