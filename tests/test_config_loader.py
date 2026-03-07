import sys
import pathlib
from pathlib import Path

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python.config_loader import load_config, DEFAULT_CONFIG_PATH


def test_load_config_default():
    config = load_config()
    assert 'watchlist' in config
    assert config['watchlist']['threshold_mb'] == 4096
    assert 'node' in config['watchlist']['processes']


def test_load_config_custom(tmp_path):
    custom_path = tmp_path / 'cfg.toml'
    custom_path.write_text('[watchlist]\nprocesses=["a"]\nthreshold_mb=1')
    config = load_config(custom_path)
    assert config['watchlist']['processes'] == ['a']
    assert config['watchlist']['threshold_mb'] == 1
