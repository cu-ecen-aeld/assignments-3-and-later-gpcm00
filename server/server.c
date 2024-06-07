#include "list.h"
#include "aesd_ioctl.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <time.h>

#define PORT     "9000"
#define BACKLOG  10
#define IPLEN    10

#define BUFFER_SZ   (1024)

#define USE_AESD_CHAR_DEVICE 1

#if USE_AESD_CHAR_DEVICE == 1

#define RECV_FILE   "/dev/aesdchar"
#define __remove_file(f)
#define __add_timer_thread(tid, thrd, f)

#else
#define RECV_FILE   "/var/tmp/aesdsocketdata"

#define __remove_file(f)    \
    if(access(f, F_OK) == 0) check(unlink(f) == -1, "unlink")

#define __add_timer_thread(tid, thrd, f)    \
    check(pthread_create(tid, NULL, thrd, (void*)f) != 0, "pthread_create")
#endif


#define __log_msg(...)  syslog(LOG_INFO, __VA_ARGS__ )  
#define __log_err(...)  syslog(LOG_ERR, __VA_ARGS__ )

#define __get_addr_in(saddr)    \
    (void*)&(((struct sockaddr_in*)&saddr)->sin_addr)

#define __close_files(l)    \
    while(l != NULL) { close(l->v); remove_list(&l, l->v); }

#define __wait_threads(t)   \
    while(t != NULL) { clean_up(t->v); }


// local data structures
struct file_lock {
    int fd;
    pthread_mutex_t lock;  
};

struct thread_args{
    int sockfd;
    char* peer_addr;
    struct file_lock* filefd;
    struct plist* lst;
};

// global variables
static struct list* fd_list = NULL;         // list of files opened
static struct list* open_threads = NULL;    // stores all opened receiving threads
static struct list* done_threads = NULL;    // stores all completed receiving

#if USE_AESD_CHAR_DEVICE == 0
// timer thread id is dealt separately because it runs throughout the whole
// program and never stops, so its termination is handled differently
static pthread_t timer_thread_id = 0;     
#endif  

// check for errors and immediately terminate
void check(bool cond, char* msg)
{ 
    if(cond) 
    { 
        if(errno == 0) errno = EINVAL;
        __log_err("%s: %s\n", msg, strerror(errno));
        closelog(); 
        exit(-1); 
    }
}

void clean_up(pthread_t tid)
{
    struct thread_args* targ;
    pthread_join(tid, (void*)&targ);
    remove_list(&fd_list, targ->sockfd);
    remove_list(&open_threads, tid);
    p_remove_list(targ->lst, tid);
    free(targ);
}

bool set_sigaction(int signum, struct sigaction* new_action)
{
    int res = 0;
    
    res = sigaction(signum, new_action, NULL);
    check(res < 0, "sigaction");
    
    return true;
}

void termination_handler(int signum)
{
    // clean up the heap and finish all pending connections
    if (signum == SIGINT || signum == SIGTERM)
    {
        __log_msg("Caught signal, exiting\n");

        __close_files(fd_list);
        
#if USE_AESD_CHAR_DEVICE == 0
        if(timer_thread_id != 0)
        {
            check(pthread_cancel(timer_thread_id) != 0, "pthread_cancel");
            void* tmp;
            pthread_join(timer_thread_id, &tmp);
            check(tmp != PTHREAD_CANCELED, "pthread_join");
        }
#endif

        __wait_threads(open_threads);
        __remove_file(RECV_FILE);

        exit(0);
    }
}

void terminate_parent(pid_t pid)
{
    if(pid != 0)
    {
        __close_files(fd_list);
        exit(0);
    }
}

#if USE_AESD_CHAR_DEVICE == 1
bool cmdec(const char* cmd, uint32_t* xrtn, uint32_t* yrtn)
{
    size_t len = strlen(cmd);
    const char* delim = " :,";
    char* token;
    uint32_t* ptr = xrtn;
    bool ret = false;
    char *str = (char*)malloc(len);
    check(str == NULL, "malloc");

    // copy string because strtok will modify the original string
    strcpy(str, cmd);

    token = strtok(str, delim);
    if(!strcmp(token, "AESDCHAR_IOCSEEKTO")) 
    {
        for(int i = 0; i < 2; i++) 
        {
            token = strtok(NULL, delim);
            *ptr = atoi(token);
            ptr = yrtn;
        }
        ret = true;
    }

    free(str);
    return ret;
}
#endif

void* recv_thread(void* args)
{
    struct thread_args* targ = (struct thread_args*) args;
    int sockfd = targ->sockfd;
    struct file_lock *file = targ->filefd;
    char* peer_addr = targ->peer_addr;
    struct plist* lst = targ->lst;
    struct aesd_seekto seekto;
    
    char* buffer = (char*)malloc(BUFFER_SZ * sizeof(char));
    check(buffer == NULL, "malloc");
    memset((void*)buffer, 0, BUFFER_SZ);
    ssize_t nread;

    // receive data and keep it in the heap for writing
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
    
    file->fd = open(RECV_FILE, O_RDWR|O_APPEND|O_CREAT, S_IROTH|S_IWOTH|S_IRGRP|S_IWGRP|S_IRUSR|S_IWUSR);
    check(file->fd == -1, "open");

#if USE_AESD_CHAR_DEVICE == 1

    if(cmdec(buffer, &seekto.write_cmd, &seekto.write_cmd_offset)) 
    {
        __log_msg("ioctl %d %d\n", seekto.write_cmd, seekto.write_cmd_offset);
        __log_msg("cmd %ld\n", AESDCHAR_IOCSEEKTO);
        check(ioctl(file->fd, AESDCHAR_IOCSEEKTO, &seekto) == -1, "ioctl");  
    } 
    else 
    {
        check(write(file->fd, buffer, nread + buffer_offset) == -1, "write");
    }

#else

    check(write(file->fd, buffer, nread + buffer_offset) == -1, "write");

    check(lseek(file->fd, 0, SEEK_SET) == -1, "lseek");   // read from the beginning of the file

#endif

    // read in chunks of "buffer_sz" and send immediately
    while((nread = read(file->fd, (void*)buffer, buffer_sz)) > 0)
    {
        check(send(sockfd, buffer, nread, 0) == -1, "send");
    }
    check(nread == -1, "read");
    
    check(close(file->fd) == -1, "close");

    pthread_mutex_unlock(&file->lock);

    free(buffer);
    
    // turn off the socket and remove it from the file descr table
    shutdown(sockfd, SHUT_RDWR);

    p_append_list(lst, pthread_self());

    __log_msg("Closed connection from %s\n", peer_addr);

    return targ; 
}

#if USE_AESD_CHAR_DEVICE == 0
void* timer_thread(void* arg)
{
    struct file_lock* file = (struct file_lock*)arg;
    char outstr[50];
    time_t t;
    struct tm *tmp;
    struct timespec clk;

    check(file->fd < 0, "file not open in the thread");

    clock_gettime(CLOCK_MONOTONIC, &clk);

    while(true) 
    {
        t = time(NULL);
        tmp = localtime(&t);
        check(tmp == NULL, "localtime");

        if(strftime(outstr, sizeof(outstr), "timestamp: %a, %d %b %Y %T %z\n", tmp) == 0)
        {
            __log_err("strftime: returned 0\n");
            exit(-1);
        }

        pthread_mutex_lock(&file->lock);
        check(write(file->fd, outstr, strlen(outstr)) == -1, "write");
        pthread_mutex_unlock(&file->lock);

        clk.tv_sec += 10;
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &clk, NULL);
    }
    return NULL;
}
#endif

int main(int argc, char** argv)
{
    openlog("aesdsocket", 0, LOG_USER);

    if(argc > 2)
    {
        __log_err("Usage: ./aesdsocket [-d]\n");
        closelog();
        exit(-1);
    }

    char* mode = argv[argc-1];
    
    bool deamon_mode = (strcmp(mode, "-d") == 0);

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
    struct sockaddr peer_addr;      // ip addr in byte format
    socklen_t peer_addr_len;
    char peer[INET_ADDRSTRLEN];     // ip addr in string format
    
    // initialize the flags for the main socket as ipv4 and tcp
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    
    // pthread compliant linked list for file descriptors
    struct plist p_fd_list;
    p_fd_list.tail = &fd_list;
    check(pthread_mutex_init(&p_fd_list.lock, NULL) != 0, "pthread_mutex_init(p_fd_list)");

    // pthread compliant linked list for threads id
    struct plist p_done_threads;
    p_done_threads.tail = &done_threads;
    check(pthread_mutex_init(&p_done_threads.lock, NULL) != 0, "pthread_mutex_init(p_done_threads)");

    // single file with a lock
    struct file_lock file;
    file.fd = -1;
    check(pthread_mutex_init(&file.lock, NULL) != 0, "pthread_mutex_init(file)");
    
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

    if(deamon_mode)
    {
        __log_msg("Initializing deamon\n");
        pid_t pid = fork();
        check(pid == -1, "fork");
        terminate_parent(pid);
    }

    // check(pthread_create(&timer_thread_id, NULL, timer_thread, (void*)&file) != 0, "pthread_create");
    __add_timer_thread(&timer_thread_id, timer_thread, &file);

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
        targ->lst = &p_done_threads;

        pthread_t thread_id = 0;

        do {
            res = pthread_create(&thread_id, NULL, recv_thread, (void*)targ);
            check(res == EINVAL || res == EPERM, "pthread_create"); 
        } while(res == EAGAIN);

        append_list(&open_threads, thread_id);

        __wait_threads(done_threads);
    }
    
    closelog();
    return 0;
}
