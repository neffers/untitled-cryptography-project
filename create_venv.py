import shutil
import venv
import sys
import setuptools
import os
import venv
from pathlib import Path

ver = sys.version_info

if not (ver.major >= 3 and ver.minor >= 8):
    print("Need at least version 3.8")
    print(f"Your current python version is {sys.version}")
    exit()

print(f"Assuming cwd as {Path.cwd()}")
try:
    # remove previous venv
    shutil.rmtree("./venv/")
except:
    pass
finally:
    venv_dir = Path(os.getcwd(), "venv")
    venv_dir.mkdir()
    venv_builder = venv.EnvBuilder(with_pip = True)
    venv_builder.create(venv_dir)
