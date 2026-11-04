import hashlib
from pathlib import Path
here = Path(__file__).resolve().parent
lines = []
for p in sorted(here.rglob("*")):
    if p.is_file() and p.name not in ("SHA256SUMS.txt", "make_sums.py") and "__pycache__" not in str(p):
        lines.append(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + str(p.relative_to(here)).replace("\\", "/"))
(here / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
