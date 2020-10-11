// RandomMinute.c -- original
#include <stdlib.h>

int RandomMinute_Get(void)
{
    int bound = 100;
    return rand() % (bound * 2 + 1);
}
