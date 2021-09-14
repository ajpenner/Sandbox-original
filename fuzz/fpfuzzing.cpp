// ©? 2020 Erik Rigtorp <erik@rigtorp.se>
// SPDX-License-Identifier: CC0-1.0

// clang++ -g -fsanitize=fuzzer fpfuzzing.cpp -o fpfuzzing

// See article at https://rigtorp.se/fuzzing-floating-point-code/

#include <algorithm>
#include <iostream>
#include <random>

double sum(const double *begin, const double *end) {
  return std::accumulate(begin, end, 0.0, [](auto a, auto b) {
    return std::isnan(b) ? a : a + b;
  });
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  double *begin = (double *)Data;
  double *end = (double *)Data + Size / sizeof(double);

  double res = sum(begin, end);

  if (std::isnan(res)) {
    std::abort();
  }

  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  double *begin = (double *)Data;
  double *end = (double *)Data + Size / sizeof(double);

  std::minstd_rand gen(Seed);

  auto rfp = [&]() {
    switch (std::uniform_int_distribution<>(0, 10)(gen)) {
    case 0:
      return std::numeric_limits<double>::quiet_NaN();
    case 1:
      return std::numeric_limits<double>::min();
    case 2:
      return std::numeric_limits<double>::max();
    case 3:
      return -std::numeric_limits<double>::min();
    case 4:
      return -std::numeric_limits<double>::max();
    case 5:
      return std::numeric_limits<double>::epsilon();
    case 6:
      return -std::numeric_limits<double>::epsilon();
    case 7:
      return std::numeric_limits<double>::infinity();
    case 8:
      return -std::numeric_limits<double>::infinity();
    case 9:
      return 0.0;
    case 10:
      std::uniform_real_distribution<> dis(-1.0, 1.0);
      return dis(gen);
    }
    return 0.0;
  };

  switch (std::uniform_int_distribution<>(0, 3)(gen)) {
  case 0: { // Change element
    if (begin != end) {
      std::uniform_int_distribution<> d(0, end - begin - 1);
      begin[d(gen)] = rfp();
    }
    break;
  }
  case 1: // Add element
    if (Size + sizeof(double) <= MaxSize) {
      *end = rfp();
      ++end;
    }
    break;
  case 2: // Delete element
    if (begin != end) {
      --end;
    }
    break;
  case 3: // Shuffle elements
    std::shuffle(begin, end, gen);
    break;
  }

  return (end - begin) * sizeof(double);
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
  // Choose elements from Data1 or Data2 with equal probability and copy to Out
  std::minstd_rand gen(Seed);
  std::bernoulli_distribution bd(0.5);
  size_t n = std::min({Size1, Size2, MaxOutSize}) / sizeof(double);
  for (size_t i = 0; i < n; ++i) {
    ((double *)Out)[i] = bd(gen) ? ((double *)Data1)[i] : ((double *)Data2)[i];
  }
  return n * sizeof(double);
}
