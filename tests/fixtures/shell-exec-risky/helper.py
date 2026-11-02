# Test fixture only: pattern examples for the scanner. Never executed.
import asyncio
import os
import subprocess


def run_tool(user_text):
    subprocess.run("tool " + user_text, shell=True)


def legacy_runner(name):
    os.system("tool " + name)


async def async_runner(name):
    await asyncio.create_subprocess_shell("tool " + name)
