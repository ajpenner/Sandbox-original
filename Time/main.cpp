#include <chrono>
#include <iostream>

struct ITMClock
{
    typedef std::chrono::seconds              duration;
    typedef duration::rep                     rep;
    typedef duration::period                  period;
    typedef std::chrono::time_point<ITMClock> time_point;
    static const bool is_steady =             false;

    static time_point now() noexcept
    {
        using namespace std::chrono;
        static uint32_t daysBetween1970And2009{14245};
        static uint32_t hoursPerDay{24};
        return time_point
          (
            duration_cast<duration>(system_clock::now().time_since_epoch()) -
            hours(daysBetween1970And2009*hoursPerDay)
          );
    }
};

int main()
{
    using namespace std::chrono;
    time_point<ITMClock> tp = ITMClock::now();
    std::cout << tp.time_since_epoch().count() << '\n';
    return 0;
}
