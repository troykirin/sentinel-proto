import tomllib
from pathlib import Path


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / 'config' / 'sentinel_config.toml'


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    """Load TOML configuration from the given path."""
    with open(path, 'rb') as f:
        return tomllib.load(f)
