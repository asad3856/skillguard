# Fixture data for the scanner only. Never executed.
from pathlib import Path

def load():
    # Local-only: history is read and summarised on this machine.
    history = load_local_history(Path.home() / ".claude" / "projects")
    return summarise_local_history(history)
