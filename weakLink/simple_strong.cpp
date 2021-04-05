#include <iostream>
#include "simple.hpp"

extern Simple::Simple(){}
extern Simple::~Simple(){}

extern void Simple::Function()
{
    std::cout << "I am strong" << std::endl;
}
