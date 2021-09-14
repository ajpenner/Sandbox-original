from html.parser import HTMLParser
from pythonfuzz.main import PythonFuzz

@PythonFuzz
def fuzz(buf):
    try:
        string = buf.decode("ascii")
        parser = HTMLParser()
        parser.feed(string)
    except UnicodeDecodeError:
        pass

# This `if` statement is here to prevent a possible long execution from happening everytime this book is built
# Just consider that we are calling the fuzz function normally
#if 0:
    fuzz()
