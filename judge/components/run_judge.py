"""Launcher so the Judge CLI can run under `python -I` (isolated: no cwd/PYTHONPATH on sys.path). argv: JUDGE_DIR then CLI args."""
import runpy, sys
sys.path.insert(0, sys.argv[1]); sys.argv = ["legion_judge"] + sys.argv[2:]
runpy.run_module("legion_judge", run_name="__main__")
