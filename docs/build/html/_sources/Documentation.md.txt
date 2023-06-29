# Documentation

This section is intendet to help you documenting your code and give you general informations about Sphinx and the used extensions.

Some useful links include:
1. [Basics Sphinx Tutorial](https://towardsdatascience.com/documenting-python-code-with-sphinx-554e1d6c4f6d)

1. [Sphinx - Python - Doc](https://www.sphinx-doc.org/en/master/index.html)

1. [MyST - Markedly Structured Text](https://myst-parser.readthedocs.io/en/latest/index.html) Tipp: They also got a Live Preview editor.

1. [Mermaid Doc](https://mermaid.js.org/intro/) Tipp there is also a Live Editor [Mermaid Live Editor](https://mermaid.live/edit)

1. [Python google style guide](https://google.github.io/styleguide/pyguide.html)

## How to update the documentation for the package

[Github-flavored Markdown](https://guides.github.com/features/mastering-markdown/)

Delete all .rst except the index.rst

Under `/`:

1. Automatic generation of Sphinx sources with: `sphinx-apidoc -fMeE -o docs/source ./src/package_mwutils/mwutils/`


Under `/docs`:

1. Remove the generated html: `make clean html`
1. Generate html documentation: `make html`
