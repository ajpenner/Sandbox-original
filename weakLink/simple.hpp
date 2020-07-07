
class Simple
{
    public:
        Simple() __attribute__((weak));
        ~Simple() __attribute__((weak));

        void Function() __attribute__((weak));
};
