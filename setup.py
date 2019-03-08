from setuptools import setup, find_packages

setup(
    name="redstone",
    version="0.1.0",
    author="Mathew Odden",
    author_email="mathewrodden@gmail.com",
    url="https://github.com/locke105/redstone",
    packages=find_packages(),
    install_requires=[
        "requests[security]"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: Apache Software License",
    ],
) 
