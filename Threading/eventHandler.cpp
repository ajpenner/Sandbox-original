#include<iostream>
#include<thread>
#include<mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
class Application
{
     std::mutex m_mutex;
     bool m_bDataLoaded;
public:
     Application()
     {
          m_bDataLoaded = false;
     }

     void loadData()
     {
          // Make This Thread sleep for 1 Second
          std::this_thread::sleep_for(std::chrono::milliseconds(1000));
          std::cout<<"Loading Data from XML"<<std::endl;

          // Lock The Data structure
          std::lock_guard<std::mutex> guard(m_mutex);
          
          // Set the flag to true, means data is loaded
          m_bDataLoaded = true;
     }

     void mainTask()
     {
          std::cout<<"Do Some Handshaking"<<std::endl;

	  // Acquire the Lock
	  m_mutex.lock();
	  // Check if flag is set to true or not
	  while(m_bDataLoaded != true)
	  {
	       // Release the lock
	       m_mutex.unlock();

               //sleep for 100 milli seconds
               std::this_thread::sleep_for(std::chrono::milliseconds(100));
	       
               // Acquire the lock
               m_mutex.lock();
          }

	  // Release the lock
	  m_mutex.unlock();
	  //Doc processing on loaded Data
	  std::cout<<"Do Processing On loaded Data"<<std::endl;
    }
};

using namespace std::placeholders;
class BetterApplication
{
  std::mutex m_mutex;
  std::condition_variable m_condVar;
  bool m_bDataLoaded;
public:
  BetterApplication()
  {
    m_bDataLoaded = false;
  }
  void loadData()
  {
   // Make This Thread sleep for 1 Second
   std::this_thread::sleep_for(std::chrono::milliseconds(1000));
   std::cout<<"Loading Data from XML"<<std::endl;
   // Lock The Data structure
   std::lock_guard<std::mutex> guard(m_mutex);
   // Set the flag to true, means data is loaded
   m_bDataLoaded = true;
   // Notify the condition variable
   m_condVar.notify_one();
  }
  bool isDataLoaded()
  {
    return m_bDataLoaded;
  }
  void mainTask()
  {
    std::cout<<"Do Some Handshaking"<<std::endl;
    // Acquire the lock
    std::unique_lock<std::mutex> mlock(m_mutex);
    // Start waiting for the Condition Variable to get signaled
    // Wait() will internally release the lock and make the thread to block
    // As soon as condition variable get signaled, resume the thread and
    // again acquire the lock. Then check if condition is met or not
    // If condition is met then continue else again go in wait.
    m_condVar.wait(mlock, std::bind(&BetterApplication::isDataLoaded, this));
    std::cout<<"Do Processing On loaded Data"<<std::endl;
  }
};

int main()
{
     Application app;

     auto now = std::chrono::high_resolution_clock::now();
     std::thread thread_1(&Application::mainTask, &app);
     std::thread thread_2(&Application::loadData, &app);

     thread_2.join();
     thread_1.join();
     auto after = std::chrono::high_resolution_clock::now();
     auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(after-now);
     std::cout << "It took me " << time_span.count() << " seconds." << std::endl;

     BetterApplication betterApp;
     now = std::chrono::high_resolution_clock::now();
     std::thread thread_3(&BetterApplication::mainTask, &betterApp);
     std::thread thread_4(&BetterApplication::loadData, &betterApp);

     thread_4.join();
     thread_3.join();
     after = std::chrono::high_resolution_clock::now();
     time_span = std::chrono::duration_cast<std::chrono::duration<double>>(after-now);
     std::cout << "It took me " << time_span.count() << " seconds." << std::endl;

     return 0;
}
