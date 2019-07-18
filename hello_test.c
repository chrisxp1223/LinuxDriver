/*
 * =====================================================================================
 *
 *       Filename:  hello_test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/18/2019 06:08:25 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
int main() {

    char buf[512];
    FILE *fp = fopen("/dev/hello_world", "w+");

    if (fp == NULL) {
        printf("can't open device!\n");
        return 0;
    }
    
    fread(buf, sizeof(buf), 1, fp);
    fwrite(buf, sizeof(buf), 1, fp);
    fclose(fp);

    return 0;
}
