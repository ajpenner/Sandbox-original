#pragma once

#include <memory>
#include <iostream>

// make forward declarations of classes that will exist
class Doer;

// make full declarations of classes
class Thinker
{
public:
  Thinker( const std::string &name ):
  mName( name )
  {}

  ~Thinker()
  {
      std::cout << "Thinker destroyed" << std::endl;
  }

  void setDoer( std::weak_ptr<Doer> doer ){ mDoer = doer; }
  std::string think();
  std::string getName() const { return mName; }
private:
  std::weak_ptr<Doer> mDoer;
  std::string         mName;
};
