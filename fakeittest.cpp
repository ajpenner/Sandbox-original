#define CATCH_CONFIG_MAIN
#include "catch2/catch.hpp"
#include "fakeit.hpp"

using namespace fakeit;

struct Dependency
{

    virtual int divide_by_two(int arg) = 0;
};

// this is the code we want to test, independently from the dependency

int half_of_ten(Dependency &dep)
{

    return dep.divide_by_two(10);
}

// this is the test

SCENARIO("Dummy test", "[dummy]")
{

    GIVEN("A mock")
    {

        Mock<Dependency> mock; // create a fake implementation of Dependency

        When(Method(mock, divide_by_two)).Return(5); // setup the return value for the mocked function

        WHEN("the half of ten is requested")
        {

            int value = half_of_ten(mock.get()); // pass the mocked Dependency

            THEN("the value is correct")
            {

                REQUIRE(value == 5);

                Verify(Method(mock, divide_by_two).Using(10)).Once(); // check divide_by_two has been called only once, with parameter 10
            }
        }
    }
}