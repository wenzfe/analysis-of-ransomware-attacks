"""Application Layer Protocol: Web Protocols

Adversaries may communicate using application layer protocols associated with web traffic 
to avoid detection/network filtering by blending in with existing traffic. 
Commands to the remote system, and often the results of those commands, 
will be embedded within the protocol traffic between the client and server.

Protocols such as HTTP and HTTPS that carry web traffic may be very common in environments. 
HTTP/S packets have many fields and headers in which data can be concealed. 
An adversary may abuse these protocols to communicate with systems under their control within 
a victim network while also mimicking normal, expected traffic.

Mitre: `T1071.001 <https://attack.mitre.org/versions/v12/techniques/T1071/004/>`_
"""

import logging
import warnings

import requests
from flask import Flask, Response, request

warnings.filterwarnings("error")
logger = logging.getLogger(__name__)


def http_cookie(url: str, data: dict, timeout: int = 1) -> dict:
    """Make a http request to the url with the data set as cookies.

    A cookie can have a maximum size of 4096 bytes (recommended).

    Args:
        url (str): The url to whicht the post request is sent to.
        data (dict): The data which gets set in the HTTP-Header as cookies.
        timeout (int): The overall timeout for a request.

    Returns:
        dict: Containing the request response cookies.
    """
    req = requests.get(url, cookies=data, timeout=timeout)
    return req.cookies.get_dict()


def webserver_factory(func: callable, path="/api") -> Flask:
    """A webserver for a HTTP cookie based communication.

    Example:
        def dummy_func(cookie_jar:dict):  # pylint: disable=W0613
            return {"response": "<response data>"}
        webserver_factory(dummy_func).run()

    Args:
        func (callable): A function with one argument representing
            the cookies (a dict) a client sent.
            The function returns the cookies as a dict to be returned to the client in the response.
        path (str, optional): Path of the endpoint. Defaults to "/api".

    Raises:
        ValueError: Is raised when a cookie contains to many characters.

    Returns:
        Flask: The webserver
    """
    app = Flask(__name__)

    @app.route(path)
    def api():
        app.logger.info("Cookies: ", request.cookies)  # pylint: disable=E1101
        cookie_jar: dict = func(request.cookies)
        response = Response()
        try:
            for key, val in cookie_jar.items():
                response.set_cookie(key, val)
        except Warning as warning:
            raise ValueError("Cookie value to long.") from warning
        return response

    return app


if __name__ == "__main__":
    pass
