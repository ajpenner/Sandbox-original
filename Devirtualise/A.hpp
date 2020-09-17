#pragma once

class A 
{
    public:
        virtual int value() { return 1; }
        virtual void magic() = 0;
};
