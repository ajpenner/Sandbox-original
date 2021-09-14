#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys

@atheris.instrument_func
def TestOneInput(data):
    if len(data) < 3:
        return

    if data == "abc":
        raise RuntimeError("Badness!")

    fdp = atheris.FuzzedDataProvider(data)
    value = fdp.ConsumeUInt(1)
    value2 = fdp.ConsumeUnicodeNoSurrogates(2)

    if value2 == "ac":
        raise RuntimeError("Caught Unicode String!")
    if value == 314:
        raise RuntimeError("Caught Specific UInt!")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
