"""
Setup configuration for REX SCAN
"""
from setuptools import setup, find_packages

setup(
    name="rex-scan",
    version="2.0.0",
    author="REX SCAN Team",
    description="Comprehensive network reconnaissance and vulnerability scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/rex_scan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "jinja2>=3.1.0",
        "colorama>=0.4.6",
        "tqdm>=4.66.0",
    ],
    extras_require={
        "full": [
            "httpx>=0.25.0",
            "aiohttp>=3.9.0",
            "playwright>=1.40.0",
            "Pillow>=10.0.0",
            "matplotlib>=3.8.0",
            "plotly>=5.18.0",
            "kaleido>=0.2.1",
            "pandas>=2.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "rex-scan=rex_scan.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "rex_scan": ["templates/*.html.j2"],
    },
)
