#ifndef SERVER_H
#define SERVER_H

#include <stdbool.h>
#include <pthread.h>

struct plist {
    struct list** tail;
    pthread_mutex_t lock;
};

struct list {
    long v;
    struct list* prev;
};

bool append_list(struct list** tail, long v);
bool remove_list(struct list** tail, long v);

bool p_append_list(struct plist* lst, long v);
bool p_remove_list(struct plist* lst, long v);

#endif
