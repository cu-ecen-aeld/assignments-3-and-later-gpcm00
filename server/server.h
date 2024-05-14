#ifndef SERVER_H
#define SERVER_H

#include <stdbool.h>
#include <pthread.h>

struct file_lock {
    int fd;
    pthread_mutex_t lock;  
};

struct plist {
    struct list** tail;
    pthread_mutex_t lock;
};

struct list {
    int fd;
    struct list* prev;
};

bool append_list(struct list** tail, int fd);
bool remove_list(struct list** tail, int fd);

bool p_append_list(struct plist* lst, int fd);
bool p_remove_list(struct plist* lst, int fd);

void check(bool cond, char* msg);

#endif
