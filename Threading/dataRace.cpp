#include <thread>
#include <vector>
#include <iostream>
#include <atomic>
#include <mutex>

class Wallet
{
    int mMoney;
public:
    Wallet() : mMoney(0) {}
    int getMoney() { return mMoney; }
    void addMoney(int money)
    {
       for(int i = 0; i < money; ++i)
       {
          mMoney++;
       }
    }
};

class LockedWallet
{
	int mMoney;
	std::mutex mutex;
public:
	LockedWallet() : mMoney(0) {}
    int getMoney()   { 	return mMoney; }
    void addMoney(int money)
    {
	mutex.lock();
    	for(int i = 0; i < money; ++i)
	{
	     mMoney++;
	}
	mutex.unlock();
    }
};

class BetterLockedWallet
{
	int mMoney;
	std::mutex mutex;
public:
	BetterLockedWallet() : mMoney(0) {}
    int getMoney()   { 	return mMoney; }
    void addMoney(int money)
    {
	std::lock_guard<std::mutex> lockGuard(mutex); // a form of RAII for the mutex, we do not worry about unlocking
    	for(int i = 0; i < money; ++i)
	{
	     mMoney++;
	}
    }
};
class AtomicWallet
{
	std::atomic<int> mMoney;
public:
	AtomicWallet() : mMoney(0) {}
    int getMoney()   { 	return mMoney; }
    void addMoney(int money)
    {
    	for(int i = 0; i < money; ++i)
	{
	     mMoney++;
	}
    }
};

int testMultithreadedWallet()
{
     Wallet walletObject;
     std::vector<std::thread> threads;
     for(int i = 0; i < 5; ++i)
     {
          threads.push_back(std::thread(&Wallet::addMoney, &walletObject, 1000));
     }

     for(int i = 0; i < threads.size() ; i++)
     {
          threads.at(i).join();
     }

     return walletObject.getMoney();
}

int testMultithreadedLockedWallet()
{
     LockedWallet walletObject;
     std::vector<std::thread> threads;
     for(int i = 0; i < 5; ++i)
     {
          threads.push_back(std::thread(&LockedWallet::addMoney, &walletObject, 1000));
     }

     for(int i = 0; i < threads.size() ; i++)
     {
          threads.at(i).join();
     }

     return walletObject.getMoney();
}

int testMultithreadedBetterLockedWallet()
{
     BetterLockedWallet walletObject;
     std::vector<std::thread> threads;
     for(int i = 0; i < 5; ++i)
     {
          threads.push_back(std::thread(&BetterLockedWallet::addMoney, &walletObject, 1000));
     }

     for(int i = 0; i < threads.size() ; i++)
     {
          threads.at(i).join();
     }

     return walletObject.getMoney();
}

int testMultithreadedAtomicWallet()
{
     AtomicWallet walletObject;
     std::vector<std::thread> threads;
     for(int i = 0; i < 5; ++i)
     {
          threads.push_back(std::thread(&AtomicWallet::addMoney, &walletObject, 1000));
     }

     for(int i = 0; i < threads.size() ; i++)
     {
          threads.at(i).join();
     }

     return walletObject.getMoney();
}

int main()
{
     int val = 0;
     for(int k = 0; k < 1000; k++)
     {
          if((val = testMultithreadedWallet()) != 5000)
          {
               std::cout << "Error at count = "<< k <<" Money in Wallet = "<< val << std::endl;
          }
     }
     
     for(int k = 0; k < 1000; k++)
     {
          if((val = testMultithreadedLockedWallet()) != 5000)
          {
               std::cout << "Error at count = "<< k <<" Money in LockedWallet = "<< val << std::endl;
          }
     }

     for(int k = 0; k < 1000; k++)
     {
          if((val = testMultithreadedBetterLockedWallet()) != 5000)
          {
               std::cout << "Error at count = "<< k <<" Money in BetterLockedWallet = "<< val << std::endl;
          }
     }

     for(int k = 0; k < 1000; k++)
     {
          if((val = testMultithreadedAtomicWallet()) != 5000)
          {
               std::cout << "Error at count = "<< k <<" Money in AtomicWallet = "<< val << std::endl;
          }
     }
     return 0;
}
