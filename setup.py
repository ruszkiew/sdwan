from setuptools import setup

setup(
   name='sdwan',
   version='1.0',
   description='Cisco SD-WAN CLI Tool',
   author='Ed Ruszkiewicz',
   author_email='ed@ruszkiewicz.net',
   packages=['sdwan'],
   install_requires=['requests', 'pysocks', 'click', 'tabulate', 'netmiko']
)
