from io import open
from os import path

from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pyebpf',
    version='1.0.4',
    description='A bcc-based Python eBPF (Extended-Berkeley-Packet-Filter) wrapper',
    long_description=long_description,  # Optional
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='https://github.com/dany74q/pyebpf',
    author='Danny Shemesh (dany74q)',
    author_email='dany74q@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='bpf ebpf',
    packages=find_packages(),
    project_urls={  # Optional
        'Bug Reports': 'https://github.com/dany74q/pyebpf/issues',
        'Source': 'https://github.com/dany74q/pyebpf/',
    }
)
