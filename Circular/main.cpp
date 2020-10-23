#include <iostream>
#include <memory>
#include "doer.hpp"
#include "thinker.hpp"

int main( int argc, const char *argv[] )
{
  auto thinker = std::make_shared<Thinker>( "Metis" );
  auto doer = std::make_shared<Doer>( "Thor", thinker );
  std::cout << thinker->think() << std::endl; // no one to think for
  thinker->setDoer( doer );         // assign complement
  std::cout << thinker->think() << std::endl;
  std::cout << doer->act() << std::endl;
  return 0;
}
