int rfoo(int *restrict a, int *restrict b)
{
    *a = 5;
    *b = 6;
    return *a + *b;
}
