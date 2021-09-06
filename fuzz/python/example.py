#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys

@atheris.instrument_func
def TestOneInput(data):
    print("Data", data)
    if len(data) < 1:
        return
    fdp = atheris.FuzzedDataProvider(data)
    value = fdp.ConsumeUInt(1)
    print("Berp", value)
    if value > 30:
        raise RuntimeError("Badness2!")
    elif value > 3:
        print("Middle")
    elif value < 3:
        print("Bottom")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
