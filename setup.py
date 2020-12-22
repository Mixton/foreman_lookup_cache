# -*- coding: utf-8 -*-
#!/usr/bin/env python
from setuptools import setup, find_packages
setup(
    name="foremanlookup-cache",
    version=0.0.1,
    long_description=open("README.md").read(),
    url="https://github.com/Mixton/foreman_lookup_cache.git",
    author="Maxime THOMAS",
    author_email="maxime.thomas@mtconsulting.tech",
    description="perf cache for foremanlookup used by puppet based on https://github.com/theforeman/puppet-foreman/blob/master/lib/puppet/parser/functions/foreman.rbhttps://github.com/theforeman/puppet-foreman/blob/master/lib/puppet/parser/functions/foreman.rb",
    keywords=["foreman", 'perf", "cache", "api", "lookup", "puppet"],
    python_requires='>=3.6',
    packages=find_packages(),
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
)
