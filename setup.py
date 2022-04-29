import setuptools


with open ("README.md", "r") as f:
    long_description = f.read()


setuptools.setup(
    name="pcan-gatewaybus",
    version="0.0.1",
    author="yunsik oh",
    author_email="oyster90@naver.com",
    description="pcan gatewaybus backend for \"python-can\"",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ys-oh/python-pcan-gatewaybus",
    packages= setuptools.find_packages(),

    classifiers=[
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],

    install_requires=[
        "python-can"
    ],

    entry_points= {
        'can.interface': [
            "gateway = gateway.gatewaybus:GatewayBus"
        ]
    }
)
