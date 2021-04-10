#include <cstdint>

void doesNothing(); // Note: declaration only

int main() 
{
    for (uint32_t i = 0; i < 1000000000; ++i) 
    {
        doesNothing();
    }

    return 0;
}
