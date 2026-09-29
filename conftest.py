import sys
from pathlib import Path

# Ensure project root is on sys.path for scripts.* imports
root = str(Path(__file__).parent.resolve())
if root not in sys.path:
    sys.path.insert(0, root)
