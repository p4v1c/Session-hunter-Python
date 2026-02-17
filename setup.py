from setuptools import setup, find_packages

setup(
    name="Session-hunter",
    version="1.0.0",
    description="Enumerate sessions Windows via RPC/SMB",
    packages=find_packages(),
    install_requires=[
        "impacket",
    ],
    entry_points={
        'console_scripts': [
            'session-hunter = session-hunter.main:main',
        ],
    },
)
