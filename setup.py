from setuptools import setup, find_packages

setup(
    name="netsec-toolkit",
    version="1.0.0",
    description="Network security toolkit — 20 tools for recon, OSINT, and exploitation",
    author="Arre",
    url="https://github.com/feelyounear/netsec-toolkit",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "dnspython>=2.3.0",
    ],
    entry_points={
        "console_scripts": [
            "netsec=netsec:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
