from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for path in ROOT.rglob("__pycache__"):
    if path.is_dir():
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
        path.rmdir()

for path in ROOT.rglob("*.pyc"):
    path.unlink(missing_ok=True)

print("Removed Python cache artifacts from working tree.")
