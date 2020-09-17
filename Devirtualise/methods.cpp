#include "A.hpp"

class B : public A 
{
    int m_member{0};
    public:
        int value() override { return 2; }
        void magic() override { m_member = 9; }
};

int test(B* b) 
{
    b->magic();
    return b->value() + 11;
}
