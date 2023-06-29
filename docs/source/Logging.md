# Logging

This Module supports logging, the following code is an example, to register and handler to a logger.

```python
    import logging

    format="%(filename)-10s %(name)-10s %(levelno)-2s %(funcName)-10s [%(message)s]"
    logging.basicConfig(level=logging.INFO, format=format)

    format = logging.Formatter(format)

    # logging for the package, change to your needs
    for pkg_module in ["mwutils", "mwutils.impact"]:
        pkg_logger = logging.getLogger(pkg_module)
        pkg_logger.addHandler(logging.StreamHandler())
        pkg_logger.setLevel(logging.INFO)
        pkg_logger.handlers[1].setFormatter(format)

    # logging for your application
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

    logging.info("Starting ...")
```