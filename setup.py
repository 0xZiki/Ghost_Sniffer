from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ghostsniffer",
    version="2.1.0",
    author="0xZiki",
    description="Hardened Modular Raw-Socket Network Reconnaissance Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "ghostsniffer=ghostsniffer.cli:main",
            "GhostSniffer=ghostsniffer.cli:main",
        ],
    },
)
