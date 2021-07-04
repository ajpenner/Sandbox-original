//#include "private_var.h"
#include "private_funct.h"
#include <stdio.h>

int main()
{
    struct Contact * Tony;
    Tony = create_contact();
    //printf( "Mobile number: %d\n", Tony->mobile_number);
    // will cause compile time error


    int * mobile_number_is_here = (int *)Tony;
    printf("Mobile number: %d\n", *mobile_number_is_here);

    int * home_number_is_here = mobile_number_is_here + 1;
    *home_number_is_here = 1;
    printf("Modified home number: %d\n", *home_number_is_here);



    delete_contact( Tony );
    return 0;
}
