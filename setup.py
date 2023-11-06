from setuptools import setup, find_packages

setup(
    name="PwnAssistor",
    version="0.2.0",
    description="Atool for pwn",
    author="V3rdant",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license="MIT",
    packages=find_packages(),
    requires=['pwntools'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)