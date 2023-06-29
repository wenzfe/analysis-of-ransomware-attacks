"""Playaudio

This module provides a tkinter frame to use to play audio files.
Credit goes to the Github repository: `audioplayer <https://github.com/mjbrusso/audioplayer>`_
"""
import logging
import os
from platform import system
from tkinter import LEFT, TOP, Button, Frame, Label, Tk, filedialog, messagebox

from audioplayer import AudioPlayer

buttons_glyph = (
    ("⏏", "▶", "⏯", "⏹") if system() == "Windows" else ("⏏️", "▶️", "⏯️", "⏹️")
)


class Audio(Frame):
    """A tkinter frame to play audio files.

    Tipp: for the window use `width=270` and `height=140`.
    """

    def __init__(self, parent: Frame, controller: Tk):
        Frame.__init__(self, parent)
        self.controller = controller

        self.player = None
        self.paused = False

        self.btnfont = (None, 30)
        self.lblfont = (None, 15)

        controller.title("Music Player")

        self.toolbar = Frame(self)
        self.toolbar.pack(side=TOP, pady=10, padx=10)
        Button(
            self.toolbar,
            text=buttons_glyph[0],
            font=self.btnfont,
            width=2,
            command=self.load,
        ).pack(side=LEFT)
        Button(
            self.toolbar,
            text=buttons_glyph[1],
            font=self.btnfont,
            width=2,
            command=self.play,
        ).pack(side=LEFT)
        Button(
            self.toolbar,
            text=buttons_glyph[2],
            font=self.btnfont,
            width=2,
            command=self.tooglepause,
        ).pack(side=LEFT)
        Button(
            self.toolbar,
            text=buttons_glyph[3],
            font=self.btnfont,
            width=2,
            command=self.stop,
        ).pack(side=LEFT)

        self.volframe = Frame(self.toolbar)
        self.volframe.pack(side=LEFT, expand=1, fill="none")
        Button(self.volframe, text="➕", command=lambda: self.changevolume(10)).pack(
            side=TOP
        )  # , expand=1, fill=BOTH
        Button(self.volframe, text="➖", command=lambda: self.changevolume(-10)).pack(
            side=TOP
        )  # , expand=1, fill=BOTH

        self.botframe = Frame(self)
        self.botframe.pack(side=TOP, expand=True)  # fill=X
        self.namelabel = Label(self.botframe)  # , font=self.lblfont
        self.namelabel.pack()  # fill=X, side=LEFT, expand=1, padx=2
        self.vollabel = Label(self.botframe, text="100%")  # , font=self.lblfont
        self.vollabel.pack()  # side=LEFT, padx=0

    def load(self):
        """Load a audio file."""
        fname = filedialog.askopenfilename()
        if fname:
            self.player = AudioPlayer(fname)
            self.changevolume(0)  # update UI
            self.namelabel.config(text=os.path.basename(self.player.fullfilename))
            try:
                self.player.play()
            except Exception as ex:  # pylint: disable=W0718
                messagebox.showerror("Error", ex)

    def tooglepause(self):
        """Pause playback."""
        if not self.player is None:
            if self.paused:
                self.player.resume()
            else:
                self.player.pause()
            self.paused = not self.paused

    def play(self):
        """Start playback."""
        if not self.player is None:
            try:
                self.player.play()
            except Exception as ex:  # pylint: disable=W0718
                messagebox.showerror("Error", ex)
                logging.info("could not play file %s", ex)

    def stop(self):
        """Stop playback."""
        if not self.player is None:
            self.player.stop()

    def changevolume(self, delta):
        """Change the volume of the played audio."""
        if not self.player is None:
            self.player.volume += delta
            self.vollabel.config(text=f"{self.player.volume}%")
