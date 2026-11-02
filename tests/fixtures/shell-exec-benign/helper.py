# Test fixture only: safe argument-list execution. Never executed.
import subprocess


def run_tool(name):
    subprocess.run(["tool", name], shell=False)


def run_checked(name):
    return subprocess.run(["tool", "--name", name], check=True)
