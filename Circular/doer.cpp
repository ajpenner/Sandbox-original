#include "doer.hpp"
#include "thinker.hpp"

std::string Doer::act()
{
  auto thinker = mThinker.lock(); // get a strong reference
  if( thinker )
  {
    return "Acting on thought considered by " + thinker->getName() + ".";
  }
  return "No to do things for.";
}

