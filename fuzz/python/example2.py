#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys

@atheris.instrument_func
def TestOneInput(data):  # Our entry point
  if len(data) != 8:
    return
  if chr(data[0]) == "d":
    if chr(data[1]) == "e":
      if chr(data[2]) == "a":
        if chr(data[3]) == "d":
          if chr(data[4]) == "b":
            if chr(data[5]) == "e":
              if chr(data[6]) == "e":
                if chr(data[7]) == "f":
                  raise RuntimeError("Error input found!")

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
