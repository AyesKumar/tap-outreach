#!/usr/bin/env python
from setuptools import setup

setup(
    name="tap-outreach",
    version="0.1.0",
    description="Singer.io tap for extracting data from the Outreach.io API",
    author="Christian Bramwell",
    url="http://singer.io",
    classifiers=["Programming Language :: Python :: 3 :: Only"],
    py_modules=["tap_outreach"],
    install_requires=[
        "singer-python==5.3.1",
        "requests",
    ],
    entry_points="""
    [console_scripts]
    tap-outreach=tap_outreach:main
    """,
    packages=["tap_outreach"],
    package_data = {
        "schemas": ["tap_outreach/schemas/*.json"]
    },
    include_package_data=True,
)
