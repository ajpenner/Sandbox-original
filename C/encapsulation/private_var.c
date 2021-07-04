#include "private_var.h"
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

void delete_contact( struct Contact * some_contact )
{
    free(some_contact);
}
