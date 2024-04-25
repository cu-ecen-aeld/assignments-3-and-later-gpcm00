#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>


int main(int argc, char **argv) 
{
	openlog(NULL, 0, LOG_USER);
	int ret = 0;
	
	if(argc != 3)
	{
		syslog(LOG_ERR, "Usage: ./writer writefile writestr\n");
		ret = 1;
		goto EXIT_CODE;
	}
	
	const char *writefile = argv[1];
	const char *writestr = argv[2];
	
	int fd;
	fd = open(writefile, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXO );
	if(fd == -1)
	{
		syslog(LOG_ERR, "Failed to open %s\n", writefile);
		ret = 1;
		goto EXIT_CODE;
	}
	
	syslog(LOG_USER, "Writing %s to %s\n", writestr, writefile);
	
	ssize_t nr;
	nr = write(fd, writestr, strlen(writestr));
	if(nr == -1)
	{
		syslog(LOG_ERR, "Failed to write to %s\n", writefile);
		ret = 1;
	}
	
	close(fd);	
	
EXIT_CODE:
	closelog();
	return ret;
}
