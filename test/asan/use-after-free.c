#include <stdlib.h>
/* Basic program to trigger a crash under Google's Address Sanitizer:

   https://code.google.com/p/address-sanitizer/wiki/AddressSanitizer#Using_AddressSanitizer
*/
int main() {
    char *x = (char*)malloc(10 * sizeof(char*));
    free(x);
    return x[5];
}
