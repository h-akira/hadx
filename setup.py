#!/usr/bin/env python3
from setuptools import setup, find_packages
import glob

def requirements_from_file(file_name):
  return open(file_name).read().splitlines()

setup(
  name='hadx',
  version='1.0.0',
  package_dir={"":"lib"},
  packages=find_packages(where="lib"),
  scripts=glob.glob("bin/*.py"),
  install_requires=requirements_from_file('requirements.txt')
)
