#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <future>

using namespace std::chrono;
std::string fetchDataFromDB(std::string recvdData)
{
    // Make sure that function takes 5 seconds to complete
    std::this_thread::sleep_for(seconds(5));
    //Do stuff like creating DB Connection and fetching Data
    return "DB_" + recvdData;
}

std::string fetchDataFromFile(std::string recvdData)
{
    // Make sure that function takes 5 seconds to complete
    std::this_thread::sleep_for(seconds(5));
    //Do stuff like fetching Data File
    return "File_" + recvdData;
}

/*
* Function Object
*/
struct DataFetcher
{
    std::string operator()(std::string recvdData)
    {
        // Make sure that function takes 5 seconds to complete
        std::this_thread::sleep_for (seconds(5));
        //Do stuff like fetching Data File
        return "FunctorFile_" + recvdData;
    }
};


int main()
{
    // Get Start Time
    system_clock::time_point start = system_clock::now();
    //Fetch Data from DB
    std::string dbData = fetchDataFromDB("Data");
    //Fetch Data from File
    std::string fileData = fetchDataFromFile("Data");
    // Get End Time
    auto end = system_clock::now();
    auto diff = duration_cast < std::chrono::seconds > (end - start).count();
    std::cout << "Total Time Taken = " << diff << " Seconds" << std::endl;

    //Combine The Data
    std::string data = dbData + " :: " + fileData;
    //Printing the combined Data
    std::cout << "Data = " << data << std::endl;

// repeat with async call around function
    // Get Start Time
    start = system_clock::now();

    // first argument to std::async is essential, otherwise we will not know if it is launching sync or async 
    std::future<std::string> resultFromDB = std::async(std::launch::async, fetchDataFromDB, "Data");
 
    //Fetch Data from File
    fileData = fetchDataFromFile("Data");
 
    //Fetch Data from DB
    // Will block till data is available in future<std::string> object.
    dbData = resultFromDB.get();
 
    // Get End Time
    end = system_clock::now();
 
    diff = duration_cast < std::chrono::seconds > (end - start).count();
    std::cout << "Total Time Taken = " << diff << " Seconds" << std::endl;
 
    //Combine The Data
    data = dbData + " :: " + fileData;
 
    //Printing the combined Data
    std::cout << "Data = " << data << std::endl;

// repeat with async call around functor
    // Get Start Time
    start = system_clock::now();

    // first argument to std::async is essential, otherwise we will not know if it is launching sync or async 
    resultFromDB = std::async(std::launch::async, DataFetcher(), "Data");
 
    //Fetch Data from File
    fileData = fetchDataFromFile("Data");
 
    //Fetch Data from DB
    // Will block till data is available in future<std::string> object.
    dbData = resultFromDB.get();
 
    // Get End Time
    end = system_clock::now();
 
    diff = duration_cast < std::chrono::seconds > (end - start).count();
    std::cout << "Total Time Taken = " << diff << " Seconds" << std::endl;
 
    //Combine The Data
    data = dbData + " :: " + fileData;
 
    //Printing the combined Data
    std::cout << "Data = " << data << std::endl;

// repeat with async call around lambda
    // Get Start Time
    start = system_clock::now();

    // first argument to std::async is essential, otherwise we will not know if it is launching sync or async 
    resultFromDB = std::async(std::launch::async, [](std::string recvdData){
						std::this_thread::sleep_for (seconds(5));
						//Do stuff like creating DB Connection and fetching Data
						return "DB_" + recvdData;
					}, "Data");
 
    //Fetch Data from File
    fileData = fetchDataFromFile("Data");
 
    //Fetch Data from DB
    // Will block till data is available in future<std::string> object.
    dbData = resultFromDB.get();
 
    // Get End Time
    end = system_clock::now();
 
    diff = duration_cast < std::chrono::seconds > (end - start).count();
    std::cout << "Total Time Taken = " << diff << " Seconds" << std::endl;
 
    //Combine The Data
    data = dbData + " :: " + fileData;
 
    //Printing the combined Data
    std::cout << "Data = " << data << std::endl;

    return 0;
}
