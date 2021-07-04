#include <stdlib.h>

int main(int argc, char* argv[]) {
        int i = atoi(argv[1]);
        // 17 in binary = 0b10001 = 1x2^4+ 1x2^0
        int b = (i << 4) + (i << 0);
}
