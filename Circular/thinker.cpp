#include <memory>
#include "thinker.hpp"
#include "doer.hpp"

std::string Thinker::think()
{
  auto doer = mDoer.lock();
  if( doer )
  {
    return "Thinking thoughts for " + doer->getName() + ".";
  }
  return "No one to think for.";
}
