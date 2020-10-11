#include <iostream>
#include "example.h"

int main()
{
    auto v = example();
    std::cout << "Here: " << v.__Default() << std::endl;
    std::cout << "Alias: " << v.someFunction() << std::endl;
}
