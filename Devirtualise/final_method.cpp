#include "A.hpp"

class C : public A 
{
    int m_member{0};
    public:
        int value() final { return 2; }
        void magic() final { m_member = 9; }
};

int test(C* c) 
{
    c->magic();
    return c->value() + 11;
}
