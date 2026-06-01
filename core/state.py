import pickle
import os

def load_state(path):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return None

def save_state(state, path):
    with open(path, "wb") as f:
        pickle.dump(state, f)

