import re

EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
PATH = re.compile(r'[A-Za-z]:\\|\\\\')

def analyze(metadata):
    text = " ".join(metadata.values())

    return {
        "author": metadata.get("Author"),
        "emails": EMAIL.findall(text),
        "paths": PATH.findall(text),
    }
