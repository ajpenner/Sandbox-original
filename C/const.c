#include <stdio.h>

void no_const(void)
{
    printf("Function: %s\n", __FUNCTION__);
	int i = 10;
	int j = 20;
	int *ptr = &i;
	/* pointer to integer */
	printf("*ptr: %d\n", *ptr);

	/* pointer is pointing to another variable */
	ptr = &j;
	printf("*ptr: %d\n", *ptr);

	/* we can change value stored by pointer */
	*ptr = 100;
	printf("*ptr: %d\n", *ptr);
}

void pointer_to_const(void)
{
    printf("Function: %s\n", __FUNCTION__);
	int i = 10;
	int j = 20;
	/* ptr is pointer to constant */
	const int *ptr = &i;

	printf("ptr: %d\n", *ptr);
	/* error: object pointed cannot be modified
	using the pointer ptr */
	//*ptr = 100;
    // Can modify the original variable. It is not constant
    i += 50;
	printf("modified value ptr: %d\n", *ptr);

	ptr = &j;		 /* valid, can reassign ptr to a different variable */
	printf("ptr: %d\n", *ptr);
}

void const_ptr_to_const(void)
{
    printf("Function: %s\n", __FUNCTION__);
	/* i is stored in read only area*/
	int const i = 10;	
	int j = 20;

	/* pointer to integer constant. Here i
	is of type "const int", and &i is of
	type "const int *". And p is of type
	"const int", types are matching no issue */
	int const *ptr = &i;		

	printf("ptr: %d\n", *ptr);

	/* error */
	//*ptr = 100;		
    //i += 30;

	/* valid. We call it up qualification. In
	C/C++, the type of "int *" is allowed to up
	qualify to the type "const int *". The type of
	&j is "int *" and is implicitly up qualified by
	the compiler to "const int *" */

	ptr = &j;		
	printf("ptr: %d\n", *ptr);
}

void non_const_ptr_to_const(void)
{
    printf("Function: %s\n", __FUNCTION__);
	int i = 10;
	int const j = 20;

	/* ptr is pointing an integer object */
	int *ptr = &i;

	printf("*ptr: %d\n", *ptr);

	/* The below assignment is invalid in C++, results in error
	In C, the compiler *may* throw a warning, but casting is
	implicitly allowed */
	ptr = &j;

	/* In C++, it is called 'down qualification'. The type of expression
	&j is "const int *" and the type of ptr is "int *". The
	assignment "ptr = &j" causes to implicitly remove const-ness
	from the expression &j. C++ being more type restrictive, will not
	allow implicit down qualification. However, C++ allows implicit
	up qualification. The reason being, const qualified identifiers
	are bound to be placed in read-only memory (but not always). If
	C++ allows above kind of assignment (ptr = &j), we can use 'ptr'
	to modify value of j which is in read-only memory. The
	consequences are implementation dependent, the program may fail
	at runtime. So strict type checking helps clean code. */

	printf("*ptr: %d\n", *ptr);
}

void const_ptr_to_var(void)
{
    printf("Function: %s\n", __FUNCTION__);
	int i = 10;
	int j = 20;

	/* constant pointer to integer */
	int *const ptr = &i;	

	printf("ptr: %d\n", *ptr);

	*ptr = 100; /* valid */
	printf("ptr: %d\n", *ptr);

	// cannot reseat the pointer
	//ptr = &j;	 /* error */
}

void const_ptr_to_const_var(void)
{
	int i = 10;
	int j = 20;
/* constant pointer to constant integer */
	const int *const ptr = &i;		

	printf("ptr: %d\n", *ptr);

    // Cannot reseat the pointer
	//ptr = &j;	 /* error */
    // Cannot modify the object the pointer is aimed at
	//*ptr = 100; /* error */
}

int main(void)
{
	no_const();
    pointer_to_const();
    const_ptr_to_const();
	non_const_ptr_to_const();
	const_ptr_to_var();

	return 0;
}
