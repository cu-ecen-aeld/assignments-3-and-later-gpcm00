#include "list.h"
#include <stdlib.h>

// thread safe append file descriptor to the list
bool p_append_list(struct plist* lst, long v)
{
    pthread_mutex_lock(&lst->lock);
    bool ret = append_list(lst->tail, v);
    pthread_mutex_unlock(&lst->lock);
    return ret;
}

// thread safe remove file descriptor from the list
bool p_remove_list(struct plist* lst, long v)
{
    pthread_mutex_lock(&lst->lock);
    bool ret = remove_list(lst->tail, v);
    pthread_mutex_unlock(&lst->lock);
    return ret;
}

// append file descriptor to the list
bool append_list(struct list** tail, long v)
{
    struct list* new_item = (struct list*)malloc(sizeof(struct list));
    if(new_item == NULL)
    {
        return false;
    }
    new_item->v = v;
    new_item->prev = *tail;
    *tail = new_item;
    
    return true;
}

// remove file descriptor from the list
bool remove_list(struct list** tail, long v)
{
    if(*tail == NULL)
    {
        return false;
    }
    
    if((*tail)->v == v)
    {
        struct list* tmp = (*tail)->prev;
        free(*tail);
        *tail = tmp;
        return true;
    }
        
    for(struct list* lst = *tail; lst->prev != NULL; lst = lst->prev)
    {
        if(lst->prev->v == v)
        {
            struct list* tmp = lst->prev;
            lst->prev = tmp->prev;
            free(tmp);
            return true;
        }
    }
    
    return false;
}