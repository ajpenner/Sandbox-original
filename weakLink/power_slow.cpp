#include <stdio.h>
#include <iostream>

#include "power_slow.hpp"

int power2(int x)
{
    std::cout << "slow power2()" << std::endl;
        return x*x;
}

int power3(int x)
{
      return power2(x)*x;
}
