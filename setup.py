from setuptools import setup, find_packages

setup(
    name=\"EthicalSecurityTools\",
    version=\"1.0.0\",
    packages=find_packages(),
    install_requires=[
        \"scapy\",
        \"yara-python\",
        \"requests\",
        \"colorama\",
    ],
    entry_points={
        \"console_scripts\": [
            \"ethical-security-tools=EthicalSecurityTools.main:main\",
        ],
    },
    author=\"Your Name\",
    author_email=\"your.email@example.com\",
    description=\"A suite of ethical security tools for file integrity monitoring, malware detection, network analysis, vulnerability scanning, and password cracking.\",
    long_description=open(\"README.md\").read(),
    long_description_content_type=\"text/markdown\",
    url=\"https://github.com/yourusername/EthicalSecurityTools\",
    classifiers=[
        \"Programming Language :: Python :: 3\",
        \"License :: OSI Approved :: MIT License\",
        \"Operating System :: OS Independent\",
        \"Development Status :: 4 - Beta\",
        \"Intended Audience :: Developers\",
        \"Intended Audience :: Science/Research\",
        \"Intended Audience :: System Administrators\",
        \"Topic :: Security\",
        \"Topic :: Software Development :: Libraries :: Python Modules\",
    ],
    python_requires=\">=3.6\",
)


