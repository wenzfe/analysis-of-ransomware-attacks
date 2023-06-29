"""Playaudio

A simple app to play audio files like `.mp3` or `.wav`.
"""

from mwutils.gui.gui_main import App
from mwutils.gui.playaudio import Audio


def run():
    """Run the application."""
    frames = ({"class": Audio, "para": {}},)
    app = App(
        visible_frame=Audio, tk_frames=frames, window_height=150, window_width=300
    )
    app.mainloop()


if __name__ == "__main__":
    run()
