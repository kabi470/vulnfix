import pickle
import subprocess
import yaml


def load_cfg(text):
    return yaml.load(text)


def restore(blob):
    return pickle.loads(blob)


def run(cmd):
    subprocess.call(cmd, shell=True)


def calc(expr):
    return eval(expr)
