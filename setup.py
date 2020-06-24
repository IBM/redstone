from setuptools import setup, find_packages

setup(
    name="redstone",
    version="0.3.0",
    author="Mathew Odden",
    author_email="mathewrodden@gmail.com",
    url="https://github.com/mrodden/redstone",
    packages=find_packages(),
    install_requires=["requests[security]", "cryptography"],
    extras_require={
        "docs": ["sphinx>=3.1", "sphinx_rtd_theme"],
    },
    entry_points={
        "console_scripts": [
            "rs-crypto = redstone.crypto.__main__:main",
            "rs-keyprotect = redstone.keyprotect.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: Apache Software License",
    ],
)
