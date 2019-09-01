#include <iostream>
#include <string>
#include <thread>

void threadCallback(int x, std::string str)
{
    std::cout<<"Passed Number = "<<x<<std::endl;
    std::cout<<"Passed String = "<<str<<std::endl;
}

void threadCallbackReference(int const & x)
{
    int & y = const_cast<int &>(x);
    y++;
    std::cout<<"Inside Thread x = "<< x <<std::endl;
}

class DummyClass {
public:
    DummyClass()
    {}
    DummyClass(const DummyClass & obj)
    {}
    void sampleMemberFunction(int x)
    {
        std::cout<<"Inside sample member function " << x << std::endl;
    }
};

int main()  
{
    int x = 10;
    std::string str = "Sample String";
    std::thread threadObj(threadCallback, x, str);
    threadObj.join();

    x = 9;
    std::cout<<"In Main Thread : Before Thread Start x = "<< x <<std::endl;
// we are intending to pass by reference, afterall the function accepts a reference
    std::thread threadObj2(threadCallbackReference, x);
    threadObj2.join();
    std::cout<<"In Main Thread : After Thread Joins x = "<< x <<std::endl;

    std::cout<<"In Main Thread : Before Thread Start x = "<< x <<std::endl;
// due to standards, we must be explicit about passing the reference
    std::thread threadObj3(threadCallbackReference, std::ref(x));
    threadObj3.join();
    std::cout<<"In Main Thread : After Thread Joins x = "<< x <<std::endl;

// dealing with member functions
    DummyClass dummyObj;
// we are explicit about which function and which object, all passed by reference
    std::thread threadObj4(&DummyClass::sampleMemberFunction, &dummyObj, x);
    threadObj4.join();

    return 0;
}
