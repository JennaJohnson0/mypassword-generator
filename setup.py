"""Setup script for MyPassword Generator."""

from setuptools import setup, find_packages
import os

# Read README file
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
long_description = "A secure password generator and manager with encrypted local storage."
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

# Read requirements
requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
requirements = []
if os.path.exists(requirements_path):
    with open(requirements_path, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="mypassword-generator",
    version="1.0.0",
    author="MyPassword Generator",
    author_email="",
    description="A secure password generator and manager with encrypted local storage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edge9/mypassword-generator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "mypassword=mypassword.cli.main:main",
            "password-generator=mypassword.cli.main:main",
        ],
    },
    keywords="password generator security encryption CLI",
    project_urls={
        "Bug Reports": "https://github.com/edge9/mypassword-generator/issues",
        "Source": "https://github.com/edge9/mypassword-generator",
    },
)