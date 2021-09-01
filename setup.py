# Copyright 2021 Mathew Odden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf8") as fh:
    long_desc = fh.read()

setup(
    name="redstone",
    version="0.5.0",
    author="Mathew Odden",
    author_email="mathewrodden@gmail.com",
    url="https://github.com/IBM/redstone",
    description="A Pythonic IBM Cloud SDK",
    long_description=long_desc,
    long_description_content_type="text/markdown",
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
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: Apache Software License",
    ],
    python_requires=">=3.6",
)
