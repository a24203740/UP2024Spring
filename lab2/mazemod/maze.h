#ifndef __MAZEMOD_H__
#define __MAZEMOD_H__

#include <asm/ioctl.h>

#define _MAZE_MAXUSER 3
#define _MAZE_MAXX    101
#define _MAZE_MAXY    101

typedef struct {
	int x, y;
}	coord_t;

typedef struct {
	int w, h;
	int sx, sy;		// initial position
	int ex, ey;		// target  position
	char blk[_MAZE_MAXY][_MAZE_MAXX];
}	maze_t;

// _IO(type,nr) and {_IOR,_IOW,_IOWR}(type,nr,size)

/*

The macro name specifies how the argument will be used. 
It may be a pointer to data to be passed into the kernel (_IOW), 
    out of the kernel (_IOR), or both (_IOWR). 
_IO can indicate either commands with no argument or those passing an integer value 
    instead of a pointer. 
It is recommended to only use _IO for commands without arguments, 
    and use pointers for passing data.

*/

/*
type
    An 8-bit number, often a character literal, specific to a subsystem or driver, and listed in Ioctl Numbers

nr
    An 8-bit number identifying the specific command, unique for a give value of 'type'

data_type
    The name of the data type pointed to by the argument, the command number encodes the sizeof(data_type) value in a 13-bit or 14-bit integer, leading to a limit of 8191 bytes for the maximum size of the argument. Note: do not pass sizeof(data_type) type into _IOR/_IOW/IOWR, as that will lead to encoding sizeof(sizeof(data_type)), i.e. sizeof(size_t). _IO does not have a data_type parameter.

*/

#define MAZE_CREATE   _IOW('M', 0, coord_t)
#define	MAZE_RESET    _IO ('M', 1)
#define	MAZE_DESTROY  _IO ('M', 2)

#define MAZE_GETSIZE  _IOR('M', 11, coord_t)
#define MAZE_MOVE     _IOW('M', 12, coord_t)
#define MAZE_GETPOS   _IOR('M', 13, coord_t)
#define MAZE_GETSTART _IOR('M', 14, coord_t)
#define MAZE_GETEND   _IOR('M', 15, coord_t)

#ifndef __KERNEL__
void maze_render_raw(maze_t *m, int cx, int cy, int shownum);
void maze_render_box(maze_t *m, int cx, int cy, int shownum);
#endif

#endif