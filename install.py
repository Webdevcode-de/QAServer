import os
import subprocess
import sys

def run(cmd):
    print(f"Running: {cmd}")
    subprocess.check_call(cmd, shell=True)

def main():
    system = os.name
    print(f"Detected OS: {system}")

    if system == "nt":
        # Windows
        run("install.cmd")
    else:
        # macOS / Linux
        run("bash install.sh")

if __name__ == "__main__":
    main()