#ifndef FAKE_CPP11_HPP
#define FAKE_CPP11_HPP



/// These definitions allow us to use some new C++11 features in previous compilers
///
/// It is strongly recommended not to copy this - just use C++11/C++14 instead!

#if __cplusplus < 201103L
#define OVERRIDE
#else
#define OVERRIDE override
#endif


#endif // FAKE_CPP11_HPP

