#pragma once

#include <memory>
#include <iostream>

// make forward declarations of classes that will exist
class Thinker;

class Doer
{
public:
  Doer( const std::string &name, std::weak_ptr<Thinker> thinker ):
  mName( name ),
  mThinker( thinker )
  {}

  ~Doer()
  {
      std::cout << "Doer destroyed" << std::endl;
  }
  std::string act();
  std::string getName() const { return mName; }
private:
  std::string            mName;
  std::weak_ptr<Thinker> mThinker;
};

