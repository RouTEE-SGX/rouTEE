#include <stdarg.h>
#include <stdio.h>

#include "Enclave.h"
#include "Enclave_t.h"

// invoke OCall to display the enclave buffer to the terminal screen
void printf(const char *fmt, ...){

    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf); // OCall
}

void printf_helloworld(){
    printf("Hello World!\n");
}
