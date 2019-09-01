#include <iostream>
#include <thread>
 
void thread_function()
{
    for(int i = 0; i < 10000; i++)
        std::cout<<"thread function Executing"<<std::endl;
}

class DisplayThread
{
public:
    void operator()()     
    {
        for(int i = 0; i < 10000; i++)
            std::cout<<"Display Thread Executing"<<std::endl;
    }
};
 
int main()  
{
	
// function pointer
    std::thread threadObj1(thread_function);
	
// functor
    std::thread threadObj2( (DisplayThread()) );
	
// lambda
    std::thread threadObj3([]{
            for(int i = 0; i < 10000; i++)
                std::cout<<"Lambda Thread Executing"<<std::endl;
            });
// this thread            
    for(int i = 0; i < 10000; i++)
        std::cout<<"Display From Main Thread"<<std::endl;
    
// wait for all threads to finish    
    threadObj1.join();    
    threadObj2.join();
    threadObj3.join();
   
   return 0;
}
