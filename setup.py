from setuptools import setup

setup(
   name='sdwan',
    version='7.8.0',
    py_modules=['sdwan'],
    install_requires=['requests', 'pysocks', 'click', 'tabulate', 'netmiko'],
    author = 'Ed Ruszkiewicz',
    author_email = 'ed@ruszkiewicz.net',
    description = 'Cisco SD-WAN CLI Tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/ruszkiew/sdwan',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
