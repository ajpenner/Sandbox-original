#include "private_funct.h"
#include <stdio.h>
#include <stdlib.h>

struct Contact
{
    int mobile_number;
    int home_number;
};


struct Contact * create_contact()
{
    struct Contact * some_contact;
    some_contact = malloc(sizeof(struct Contact));
    some_contact->mobile_number = 12345678;
    some_contact->home_number = 87654321;
    return( some_contact );
}

static void print_numbers( struct Contact * some_contact )
{
    printf("Mobile number: %d, ", some_contact->mobile_number);
    printf("home number = %d\n", some_contact->home_number);
}

void delete_contact( struct Contact * some_contact )
{
    print_numbers(some_contact);
    free(some_contact);
}
