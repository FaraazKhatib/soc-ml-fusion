import os

class JSONFileTailer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.position = os.path.getsize(filepath) if os.path.exists(filepath) else 0

    def read_new_lines(self):
        if not os.path.exists(self.filepath):
            return []

        current_size = os.path.getsize(self.filepath)
        if current_size < self.position:
            self.position = 0  # rotated

        lines = []
        with open(self.filepath, "r") as f:
            f.seek(self.position)
            lines = f.readlines()
            self.position = f.tell()

        return lines
