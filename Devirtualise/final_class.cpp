#include "A.hpp"

class D final : public A 
{
    int m_member{0};
    public:
        int value() override { return 2; }
        void magic() override { m_member = 9; }
};

int test(D* d) 
{
    d->magic();
    return d->value() + 11;
}
