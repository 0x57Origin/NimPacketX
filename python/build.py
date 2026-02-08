#!/usr/bin/env python3
"""
Build script for NimPacket Python extension

This script compiles the Nim source code into a Python extension module
using nimpy.

Requirements:
    - Nim compiler (1.6.0+)
    - nimpy package: nimble install nimpy

Usage:
    python build.py           # Build the extension
    python build.py --clean   # Clean build artifacts
    python build.py --test    # Build and run tests
"""

import os
import sys
import shutil
import subprocess
import platform


def get_extension_suffix():
    """Returns the correct extension suffix for the current platform"""
    if platform.system() == "Windows":
        return ".pyd"
    elif platform.system() == "Darwin":
        return ".so"  # macOS uses .so for Python extensions
    else:
        return ".so"


def find_nim():
    """Finds the Nim compiler"""
    nim_path = shutil.which("nim")
    if nim_path:
        return nim_path

    # Check common installation paths
    common_paths = [
        os.path.expanduser("~/.nimble/bin/nim"),
        os.path.expanduser("~/nim/bin/nim"),
        "/usr/local/bin/nim",
        "/usr/bin/nim",
    ]

    if platform.system() == "Windows":
        common_paths.extend([
            r"C:\Nim\bin\nim.exe",
            r"C:\Users\%USERNAME%\.nimble\bin\nim.exe",
        ])

    for path in common_paths:
        expanded = os.path.expandvars(path)
        if os.path.exists(expanded):
            return expanded

    return None


def check_nimpy():
    """Checks if nimpy is installed"""
    try:
        result = subprocess.run(
            ["nimble", "list", "-i"],
            capture_output=True,
            text=True
        )
        return "nimpy" in result.stdout
    except Exception:
        return False


def install_nimpy():
    """Installs nimpy using nimble"""
    print("Installing nimpy...")
    try:
        subprocess.run(
            ["nimble", "install", "nimpy", "-y"],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def build_extension():
    """Builds the Nim Python extension"""
    # Paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(script_dir, "..", "src")
    nim_source = os.path.join(src_dir, "nimpacket_py.nim")
    output_dir = os.path.join(script_dir, "nimpacket")

    # Check Nim is available
    nim_path = find_nim()
    if not nim_path:
        print("ERROR: Nim compiler not found!")
        print("Please install Nim from https://nim-lang.org/install.html")
        return False

    print(f"Found Nim at: {nim_path}")

    # Check nimpy is installed
    if not check_nimpy():
        print("nimpy not found, installing...")
        if not install_nimpy():
            print("ERROR: Failed to install nimpy")
            print("Try running: nimble install nimpy")
            return False

    # Check source file exists
    if not os.path.exists(nim_source):
        print(f"ERROR: Source file not found: {nim_source}")
        return False

    # Build command
    extension_suffix = get_extension_suffix()
    output_name = f"nimpacket_py{extension_suffix}"
    output_path = os.path.join(output_dir, output_name)

    cmd = [
        nim_path, "c",
        "--app:lib",
        f"--out:{output_path}",
        "-d:release",
        "--opt:speed",
        "--threads:on",
        f"--path:{src_dir}",
        nim_source
    ]

    print(f"Building {output_name}...")
    print(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            cwd=src_dir,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("Build failed!")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False

        print(f"Build successful! Output: {output_path}")
        return True

    except Exception as e:
        print(f"Build error: {e}")
        return False


def clean():
    """Cleans build artifacts"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "nimpacket")

    patterns = ["*.pyd", "*.so", "*.dylib", "*.c", "*.h"]
    cleaned = 0

    for pattern in patterns:
        import glob
        for f in glob.glob(os.path.join(output_dir, pattern)):
            os.remove(f)
            print(f"Removed: {f}")
            cleaned += 1

    # Clean nimcache
    src_dir = os.path.join(script_dir, "..", "src")
    nimcache = os.path.join(src_dir, "nimcache")
    if os.path.exists(nimcache):
        shutil.rmtree(nimcache)
        print(f"Removed: {nimcache}")
        cleaned += 1

    print(f"Cleaned {cleaned} items")


def run_tests():
    """Runs the Python tests"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    examples_dir = os.path.join(script_dir, "examples")

    # Run basic test
    test_file = os.path.join(examples_dir, "basic_usage.py")
    if os.path.exists(test_file):
        print(f"Running {test_file}...")
        subprocess.run([sys.executable, test_file])


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--clean":
            clean()
        elif sys.argv[1] == "--test":
            if build_extension():
                run_tests()
        elif sys.argv[1] == "--help":
            print(__doc__)
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Use --help for usage information")
    else:
        build_extension()


if __name__ == "__main__":
    main()
