# Python Packages

This [Python - Packaging Python Projects tutorial](https://packaging.python.org/en/latest/tutorials/packaging-projects/) explains the basics of building and distributing Python Packages.


The Python Package Index you probably are familiar with is the [Python Package Index (PyPI)](https://pypi.org/). But there are [more possible options](https://packaging.python.org/en/latest/guides/hosting-your-own-index/)
like a webserver, the [devpi](https://devpi.net/docs/devpi/devpi/stable/%2Bd/index.html) Project or the [pypiserver](https://github.com/pypiserver/pypiserver) Project that allow the distribution of your packages. These options allow also to host your packages in a private manner, which is required due to the  malicious code they contain. 

## Build a package
```sh
py -m build
```

### Upload a package
For more information about possible options when publishing Python packages to a Package Index with `twine` look at: [Twine - Doc](https://twine.readthedocs.io/en/stable/#)

```sh
py -m twine upload --repository <package index> dist/*
```

### Install a package
```sh
pip install --index-url <package index> --no-deps <package_name>
```
