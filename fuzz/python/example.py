#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys

@atheris.instrument_func
def TestOneInput(data):
    print("Data:", data)
    if len(data) < 10:
        return

    if data == "abc":
        raise RuntimeError("Badness!")

    fdp = atheris.FuzzedDataProvider(data)
    value = fdp.ConsumeUInt(1)
    value2 = fdp.ConsumeUnicodeNoSurrogates(2)
    print("UInt:", value)
    print("String: ", value2)
    if value2 == "ac":
        raise RuntimeError("Caught Unicode String!")
    elif value > 3:
        print("Middle")
    elif value < 3:
        print("Bottom")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
