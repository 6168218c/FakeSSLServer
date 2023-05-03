#ifndef SUNK_SHARED_H
#define SUNK_SHARED_H
#include <stdbool.h>
#include <stdio.h>
extern bool globalStop;
#define FAILFAST(function, msg)                       \
    perror("Error occurred in [" #function "]:" msg); \
    exit(EXIT_FAILURE);
#define LOGERROR(category, msg) perror("Error occurred in [" #category "] " msg);
#endif