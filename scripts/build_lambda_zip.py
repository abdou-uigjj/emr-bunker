"""Package the response lambda: playbook/ + canary/ + lambda/ -> lambda.zip.

The zip root is the repo root, so the handler is
lambda/response/handler.handler and its `import playbook.core` works.
"""

import os
import zipfile

ROOTS = ["playbook", "canary", "lambda"]
OUT = "lambda.zip"


def build() -> int:
    if os.path.exists(OUT):
        os.remove(OUT)
    n = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for root in ROOTS:
            for dirpath, _dirs, files in os.walk(root):
                for f in files:
                    full = os.path.join(dirpath, f)
                    if f.endswith((".pyc",)) or "__pycache__" in dirpath:
                        continue
                    zf.write(full, os.path.relpath(full))
                    n += 1
    return n


if __name__ == "__main__":
    count = build()
    print(f"built {OUT} with {count} files")
