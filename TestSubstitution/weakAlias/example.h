#pragma once

class example
{
    public:
        example() = default;
        ~example() = default;
        int __Default()
        {
            return 42;
        }
        int someFunction() __attribute__((weak, alias("_ZN7example9__DefaultEv")));

        //int another() __attribute__ ((weak, alias ("_ZN7example12someFunctionEv")));
};
