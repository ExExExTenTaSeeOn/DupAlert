# setup.py

from setuptools import setup, find_packages

setup(
    name="ddas",
    version="1.0.0",
    description="A versatile CLI tool that handles multiple subcommands like 'hello', 'wget', 'curl', and executes Python and Bash scripts.",
    author="Your Name",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "ddas=ddas:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests",
        "pyxattr; platform_system=='Linux' or platform_system=='Darwin'",
    ],
)
