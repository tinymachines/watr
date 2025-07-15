from setuptools import setup, find_packages

setup(
    name="watr",
    version="1.0.0",
    packages=find_packages(where="python"),
    package_dir={"": "python"},
    install_requires=[
        "pybind11>=2.10.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ]
    },
    python_requires=">=3.8",
)