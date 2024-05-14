#include "server.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>

#define PORT     "9000"
#define BACKLOG  10
#define IPLEN    10

#define FD_STACK_SZ 13

#define BUFFER_SZ   (1024)

#define RECV_FILE   "/var/tmp/aesdsocketdata"

#define __log_msg(...)  syslog(LOG_INFO, __VA_ARGS__ )  
#define __log_err(...)  syslog(LOG_ERR, __VA_ARGS__ )

#define __get_addr_in(saddr)    \
    (void*)&(((struct sockaddr_in*)&saddr)->sin_addr)

#define __wait_all_threads(t)   \
    for(int i = 0; i < open_threads.count; i++) \
        check(pthread_join(t.threads[i], NULL) != 0, "pthread_join")

#define __clean_list(l)         \
    while(l != NULL) { close(l->fd); remove_list(&l, l->fd); }

bool set_sigaction(int signum, struct sigaction* new_action)
{
    int res = 0;
    
    res = sigaction(signum, new_action, NULL);
    check(res < 0, "sigaction");
    
    return true;
}

static struct list* fd_list = NULL;

static struct open_threads{
    pthread_t threads[BACKLOG];
    size_t count;
} open_threads;
void termination_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        __log_msg("Caught signal, exiting\n");

        __wait_all_threads(open_threads);

        __clean_list(fd_list);  

        if(access(RECV_FILE, F_OK) == 0)
        {
            check(unlink(RECV_FILE) == -1, "unlink");
        } 
        exit(0);
    }
}

void terminate_parent(pid_t pid)
{
    if(pid != 0)
    {
        __clean_list(fd_list);
        exit(0);
    }
}

struct thread_args{
    int sockfd;
    char* peer_addr;
    struct file_lock* filefd;
    struct plist* lst;
};

void* recv_thread(void* args)
{
    struct thread_args* targ = (struct thread_args*) args;
    int sockfd = targ->sockfd;
    struct file_lock *file = targ->filefd;
    char* peer_addr = targ->peer_addr;
    struct plist* lst = targ->lst;
    
    char* buffer = (char*)malloc(BUFFER_SZ * sizeof(char));
    check(buffer == NULL, "malloc");
    memset((void*)buffer, 0, BUFFER_SZ);
    ssize_t nread;

    check(file->fd < 0, "file not open in the thread");

    off_t buffer_offset = 0;
    ssize_t buffer_sz = BUFFER_SZ;
    while((nread = recv(sockfd, (void*)(buffer + buffer_offset), BUFFER_SZ, 0)) == BUFFER_SZ)
    {
        buffer_offset += BUFFER_SZ;
        buffer_sz += BUFFER_SZ;
        buffer = (char*)realloc(buffer, buffer_sz * sizeof(char));
        check(buffer == NULL, "realloc");
        memset((void*)(buffer + buffer_offset), 0, BUFFER_SZ);
    }
    check(nread == -1, "recv");

    pthread_mutex_lock(&file->lock);

    check(write(file->fd, buffer, nread + buffer_offset) == -1, "write");

    check(lseek(file->fd, 0, SEEK_SET) < 0, "lseek");

    while((nread = read(file->fd, (void*)buffer, buffer_sz)) == buffer_sz)
    {
        check(send(sockfd, buffer, nread, 0) == -1, "send");
    }

    check(nread == -1, "read");

    pthread_mutex_unlock(&file->lock);

    check(send(sockfd, buffer, nread, 0) == -1, "send");
    
    shutdown(sockfd, SHUT_RDWR);

    p_remove_list(lst, sockfd);

    free(targ);
    free(buffer);

    __log_msg("Closed connection from %s\n", peer_addr);

    return NULL; 
}


int main(int argc, char** argv)
{
    openlog("aesdsocket", 0, LOG_USER);

    if(argc > 2)
    {
        __log_err("Usage: ./aesdsocket [-p]\n");
        exit(-1);
    }

    char* mode = argv[argc-1];

    bool is_deamon = strcmp(mode, "-d") == 0;

    // initialize graceful termination
    struct sigaction term;
    term.sa_handler = termination_handler;
    sigemptyset(&term.sa_mask);
    term.sa_flags = 0;
    
    set_sigaction(SIGINT, &term);
    set_sigaction(SIGTERM, &term);
    
    // sockets fds for the whole system and for the each connection
    int sfd = 0, sockfd = 0;
    
    // to check the return value of functions
    int res = 0;    // never use it for long term memory
    
    // variables that hold socket info
    struct addrinfo hints, *rp, *result;
    struct sockaddr peer_addr;
    socklen_t peer_addr_len;
    char peer[INET_ADDRSTRLEN];
    
    // initialize the flags for the main socket
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    
    // pthread compliant linked list
    struct plist p_fd_list;
    p_fd_list.tail = &fd_list;
    check(pthread_mutex_init(&p_fd_list.lock, NULL) < 0, "pthread_mutex_init(p_fd_list)");
    
    // single file with a lock
    struct file_lock file;
    file.fd = -1;
    check(pthread_mutex_init(&file.lock, NULL) < 0, "pthread_mutex_init(file)");
    
    // get available address automatically
    res = getaddrinfo(NULL, PORT, &hints, &result);
    if(res != 0)
    {
        __log_err("getaddrinfo: %s\n", gai_strerror(res));
        closelog();
        exit(-1);
    }
    
    // initialze the first available address
    for(rp = result; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(sfd == -1)
        {
            __log_err("socket: %s\n", strerror(errno));
            continue;
        }
        
        const int enable = 1;
        res = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
        
        res = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        check(res != 0, "bind");
        break;
    }
 
    check(rp == NULL, "NULL socket");
    __log_msg("Successfully binded socket at port %s", PORT);
    
    freeaddrinfo(result);   // only to get the address automatically (results is useless now)
    
    check(!append_list(&fd_list, sfd), "append(sfd)");

    if(is_deamon)
    {
        __log_msg("Initializing deamon\n");
        pid_t pid = fork();
        check(pid == -1, "fork");
        terminate_parent(pid);
    }
    
    // open temp file that we will use to store whatever we receive
    file.fd = open(RECV_FILE, O_RDWR|O_APPEND|O_CREAT, S_IROTH|S_IWOTH|S_IRGRP|S_IWGRP|S_IRUSR|S_IWUSR);
    check(file.fd == -1, "open");
    check(!append_list(&fd_list, file.fd), "append(file.fd)");

    // start listening for connections
    res = listen(sfd, BACKLOG);
    check(res != 0, "listen");
    
    // continuously check for connections and handle it in another thread
    while(true)
    {
        peer_addr_len = sizeof(struct sockaddr_storage);
        sockfd = accept(sfd, &peer_addr, &peer_addr_len);
        check(sockfd == -1, "accept");
        
        // get the ip in string format
        if(inet_ntop(peer_addr.sa_family, __get_addr_in(peer_addr), peer, sizeof(peer)) != NULL)
        {
            __log_msg("Accepted connection from %s\n", peer);
        }
        else
        {
            __log_err("inet_ntop: %s\n", strerror(errno));
        }
        
        check(!p_append_list(&p_fd_list, sockfd), "append(sockfd)");
        
        // create receiver thread
        struct thread_args* targ = (struct thread_args*)malloc(sizeof(struct thread_args));
        targ->sockfd = sockfd;
        targ->filefd = &file;
        targ->peer_addr = peer;
        targ->lst = &p_fd_list;
        pthread_create(&open_threads.threads[open_threads.count], NULL, recv_thread, (void*)targ);
        open_threads.count++;

        // this prevents more backlogs than possible
        if(open_threads.count >= BACKLOG)
        {
            for(int i = 0; i < open_threads.count; i++)
            {
                pthread_join(open_threads.threads[i], NULL);
                __log_msg("Thread %ld completed\n", open_threads.threads[i]);
            }
            open_threads.count = 0;
        }
        
    }
    
    closelog();
    return 0;
}

bool p_append_list(struct plist* lst, int fd)
{
    pthread_mutex_lock(&lst->lock);
    bool ret = append_list(lst->tail, fd);
    pthread_mutex_unlock(&lst->lock);
    return ret;
}

bool p_remove_list(struct plist* lst, int fd)
{
    pthread_mutex_lock(&lst->lock);
    bool ret = remove_list(lst->tail, fd);
    pthread_mutex_unlock(&lst->lock);
    return ret;
}

bool append_list(struct list** tail, int fd)
{
    struct list* new_item = (struct list*)malloc(sizeof(struct list));
    if(new_item == NULL)
    {
        __log_err("malloc failed\n");
        return false;
    }
    new_item->fd = fd;
    new_item->prev = *tail;
    *tail = new_item;
    
    return true;
}

bool remove_list(struct list** tail, int fd)
{
    if(*tail == NULL)
    {
        return false;
    }
    
    if((*tail)->fd == fd)
    {
        struct list* tmp = (*tail)->prev;
        free(*tail);
        *tail = tmp;
        return true;
    }
    
    struct list* lst = *tail;
    
    while(lst->prev != NULL)
    {
        if(lst->prev->fd == fd)
        {
            struct list* tmp = lst->prev;
            lst->prev = tmp->prev;
            free(tmp);
            return true;
        }
        lst = lst->prev;
    }
    
    return false;
}

void check(bool cond, char* msg)
{ 
    if(cond) 
    { 
        __log_err("%s: %s\n", msg, strerror(errno));
        closelog(); 
        exit(-1); 
    }
}