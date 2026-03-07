import subprocess
import sys
import os


def test_main_output():
    result = subprocess.check_output(
        [sys.executable, os.path.join('python', 'main.py')],
        text=True,
    )
    assert result.strip() == 'Sentinel Python CLI running...'
