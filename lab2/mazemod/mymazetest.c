#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "maze.h"

#define	DEVFILE	"/dev/maze"



int main() {
	int fd;
	char buf[64];
	if((fd = open(DEVFILE, O_RDWR)) < 0) {
		perror("open");
		return -1;
	}

	coord_t cord;
	cord.x = 10;
	cord.y = 10;

	printf("pid=%d\n", getpid());


	read(fd, buf, sizeof(buf));
	write(fd, buf, sizeof(buf));
	ioctl(fd, MAZE_CREATE, &cord);
	ioctl(fd, MAZE_RESET);
	ioctl(fd, MAZE_DESTROY);
	ioctl(fd, MAZE_GETSIZE, &cord); 
	ioctl(fd, MAZE_MOVE, &cord);    
	ioctl(fd, MAZE_GETPOS, &cord);  
	ioctl(fd, MAZE_GETSTART, &cord);
	ioctl(fd, MAZE_GETEND, &cord);  

	close(fd);

	return 0;
}
