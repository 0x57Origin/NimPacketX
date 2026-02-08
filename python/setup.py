"""
NimPacket Python Package Setup

This package provides Python bindings for the NimPacket low-level
packet manipulation library.

Installation:
    pip install .

Development installation:
    pip install -e .

Building the Nim extension:
    python build.py
"""

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

# Read the README for long description
readme_path = os.path.join(here, "..", "docs", "PythonBinding.md")
if os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "NimPacket - Python bindings for low-level packet manipulation"

setup(
    name="nimpacket",
    version="0.2.0",
    author="0x57Origin",
    author_email="",
    description="Python bindings for NimPacket - Low-level packet manipulation library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/0x57Origin/NimPacket",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
    },
    keywords=[
        "network",
        "packet",
        "security",
        "tcp",
        "udp",
        "icmp",
        "dns",
        "dhcp",
        "ethernet",
        "arp",
        "ipv4",
        "ipv6",
        "raw socket",
        "packet crafting",
    ],
    project_urls={
        "Bug Reports": "https://github.com/0x57Origin/NimPacket/issues",
        "Source": "https://github.com/0x57Origin/NimPacket",
        "Documentation": "https://github.com/0x57Origin/NimPacket/blob/main/docs/PythonBinding.md",
    },
    include_package_data=True,
    package_data={
        "nimpacket": ["*.pyd", "*.so", "*.dylib"],
    },
)
