"""Tkinter App

A main/wrapper module for tkinter frames.


Tkinter Frames that can be used and are included in this subpackage are:

#. ransomware

#. playaudio

The following example code gives an idea how to work with this module.

.. code:: python

    import sys
    
    from mwutils.gui.ransomware import RW
    from mwutils.gui.playaudio import Audio
    from mwutils.gui.gui_main import App

    if __name__ == "__main__":

        FORMAT = "[%(asctime)s] [%(funcName)-30s] [%(levelname)-8s] [%(message)s]"
        logging.basicConfig(stream=sys.stderr, encoding="utf-8", format=FORMAT, level=0)


        def rw_func():
            logger.info("executing rw_func")
            app.show_frame(RW.__name__)

        def rw_dec_func():
            logger.info("executing rw_dec_func")


        frames = (
            {"class": RW, "para": {"decrypt_function": rw_dec_func}},
            {'class': Audio, 'para': {}},
        )
        app = App(
            tk_frames=frames,
            visible_frame=Audio,
            window_width=800, window_height=300
        )

        # runs after the loop and can execute your code
        app.after(2000, rw_func)
        app.mainloop()
"""

import logging
from tkinter import Frame, Tk
from typing import Type

logger = logging.getLogger(__name__)


class App(Tk):
    """The main gui app

    Example:
        frames = (
            {'class': Audio, 'para': {}},
        )

        app = App(
            tk_frames=frames,
            visible_frame=Audio,
            window_width=270,
            window_height=140,
        )

        app.mainloop()

    Args:
        Tk (_type_): Tkinter app
    """

    def __init__(
        self,
        tk_frames: tuple,
        visible_frame: Type[Frame],
        *args,
        window_width: int = 500,
        window_height: int = 500,
        **kwargs,
    ):
        """Tkinter App

        Args:
            tk_frames (tuple): Of dicts with the class and the parameters for the frame.
                See example.
            visible_frame (Type[Frame]): The tkinter frame to show initially.
            window_width (int, optional): Window width. Defaults to 500.
            window_height (int, optional): Window height. Defaults to 500.

        Example:
            frames = (
                {'class': Audio, 'para': {}},
            )

            app = App(
                tk_frames=frames,
                visible_frame=Audio,
                window_width=270,
                window_height=140,
            )

            app.mainloop()
        """
        Tk.__init__(self, *args, **kwargs)

        screen_width = int((self.winfo_screenwidth() / 2) - (window_width / 2))
        screen_height = int((self.winfo_screenheight() / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{screen_width}+{screen_height}")
        self.resizable(width=True, height=True)

        container = Frame(self)
        container.pack(side="top", fill="both", expand=True)

        self.frames = {}
        for F in tk_frames:
            self.frames[F["class"].__name__] = F["class"](
                parent=container, controller=self, **F["para"]
            )
            self.frames[F["class"].__name__].grid(row=0, column=0, sticky="nsew")

        self.show_frame(visible_frame.__name__)

    def show_frame(self, frame_name: str):
        """The Tkinter Frame to show.

        Tipp: use `<class>.__name__` to get the name of the frame.

        Args:
            frame_name (str): The frame to show.
        """
        frame = self.frames[frame_name]
        frame.tkraise()
