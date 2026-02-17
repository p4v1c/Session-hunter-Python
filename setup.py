from setuptools import setup

setup(
    name="session-hunter",
    version="1.0.0",
    description="Real-time Windows session monitoring tool",
    author="p4v1c",
    url="https://github.com/p4v1c/Session-hunter-Python",
    py_modules=["session_hunter"],

    install_requires=[
        "impacket",
    ],
    entry_points={
        'console_scripts': [
            'session-hunter = session_hunter:main',
        ],
    },
    python_requires='>=3.6',
)
