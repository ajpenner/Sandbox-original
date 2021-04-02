#include "RandomMinute.h"
#include "SomeClass.hpp"
#include <iostream>

int main()
{
    std::cout << "Random value: " << RandomMinute_Get() << std::endl;

    auto sc = SomeClass();
    std::cout << "Class value: " << sc.Value() << std::endl;
}
