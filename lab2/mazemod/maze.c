/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "maze.h"

// * A static global variable or a function is "seen" only in the file it's declared in

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static maze_t maze[_MAZE_MAXUSER];
static pid_t mazeOwner[_MAZE_MAXUSER];
static coord_t mazeCurPos[_MAZE_MAXUSER];

static DEFINE_MUTEX(mazeOwnershipMutex);
static DEFINE_MUTEX(mazeDataMutex);

// * static functions are functions that are only visible to other functions in the same file

/* 
* In C, int foo() and int foo(void) are different functions. 
* int foo() accepts an arbitrary number of arguments, 
* while int foo(void) accepts 0 arguments
ref: https://stackoverflow.com/questions/42125/warning-error-function-declaration-isnt-a-prototype
*/
static void initDevice(void)
{
	for(size_t i = 0; i < _MAZE_MAXUSER; i++)
	{
		maze[i].w = 0;
		mazeOwner[i] = -1;
	}
}

/*
// uid_t = __kernel_uid32_t = unsigned int
static uid_t get_current_uid(void)
{
	// marco in cred.h, expand to current_cred()->uid
	// the type of current_uid() is kuid_t
	// which is a struct wrapper of uid_t
	// current_cred() is inside sched.h
	return current_uid().val;
}
*/

// pid_t = int
static pid_t getCurrentPid(void)
{
	// https://linux.laoqinren.net/kernel/sched/current/
	return current->pid;
}

static short getMazeOwnedByProcess(pid_t pid)
{
	for(size_t i = 0; i < _MAZE_MAXUSER; i++)
	{
		if(mazeOwner[i] == pid)
		{
			return i;
		}
	}
	return -1;
}

// static short findEmptyMazeSlot(void)
// {
// 	mutex_lock(&mazeOwnershipMutex);
// 	for(size_t i = 0; i < _MAZE_MAXUSER; i++)
// 	{
// 		if(mazeOwner[i] == -1)
// 		{
// 			mutex_unlock(&mazeOwnershipMutex);
// 			return i;
// 		}
// 	}
// 	mutex_unlock(&mazeOwnershipMutex);
// 	return -1;
// }

static short findAndSetEmptyMazeSlot(pid_t pid)
{
	mutex_lock(&mazeOwnershipMutex);
	for(size_t i = 0; i < _MAZE_MAXUSER; i++)
	{
		if(mazeOwner[i] == -1)
		{
			mazeOwner[i] = pid;
			mutex_unlock(&mazeOwnershipMutex);
			return i;
		}
	}
	mutex_unlock(&mazeOwnershipMutex);
	return -1;
}

static void destroyMaze(size_t index)
{
	mutex_lock(&mazeDataMutex);
	mutex_lock(&mazeOwnershipMutex);
	maze[index].w = 0;
	mazeOwner[index] = -1;
	mutex_unlock(&mazeOwnershipMutex);
	mutex_unlock(&mazeDataMutex);
}

static short checkIfAMoveIsLegal(coord_t move)
{
	if(
		(move.x == 0 && move.y == 1) ||
		(move.x == 0 && move.y == -1) ||
		(move.x == 1 && move.y == 0) ||
		(move.x == -1 && move.y == 0)
	)
	{
		return 1;
	}
	return 0;
}

static void moveInAMaze(size_t index, coord_t move)
{
	int x = mazeCurPos[index].x + move.x;
	int y = mazeCurPos[index].y + move.y;
	if(x < 0 || x >= maze[index].w || y < 0 || y >= maze[index].h)
	{
		return;
	}
	if(maze[index].blk[y][x] == 0)
	{
		mazeCurPos[index].x = x;
		mazeCurPos[index].y = y;
	}
}

static void printMaze(struct seq_file *m, size_t index)
{
	if(mazeOwner[index] == -1)
	{
		seq_printf(m, "#%02lu: vacancy\n\n", index);
		return;
	}
	seq_printf(m, "#%02lu: pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n", 
			index, mazeOwner[index], 
			maze[index].w, maze[index].h, 
			maze[index].sx, maze[index].sy,
			maze[index].ex, maze[index].ey, 
			mazeCurPos[index].x, mazeCurPos[index].y);
	for(size_t y = 0; y < maze[index].h; y++)
	{
		seq_printf(m, "- %03lu: ", y);
		for(size_t x = 0; x < maze[index].w; x++)
		{
			if(y == mazeCurPos[index].y && x == mazeCurPos[index].x)
			{
				seq_printf(m, "*");
			}
			else if(y == maze[index].sy && x == maze[index].sx)
			{
				seq_printf(m, "S");
			}
			else if(y == maze[index].ey && x == maze[index].ex)
			{
				seq_printf(m, "E");
			}
			else if(maze[index].blk[y][x] == 0)
			{
				seq_printf(m, ".");
			}
			else
			{
				seq_printf(m, "#");
			}
		}
		seq_printf(m, "\n");
	}
}

static void generateRandomMaze(size_t index, int inputW, int inputH)
{
	mutex_lock(&mazeDataMutex);
	for(int y = 0; y < inputH; y++)
	{
		for(int x = 0; x < inputW; x++)
		{
			maze[index].blk[y][x] = 1;
		}
	}
	int w = inputW;
	int h = inputH;
	if(w % 2 == 0) w--;
	if(h % 2 == 0) h--;
	// printk(KERN_INFO "generateRandomMaze: function start\n");
	maze[index].w = inputW;
	maze[index].h = inputH;
	maze[index].sx = 2 * (get_random_u32() % (w / 2)) + 1;
	maze[index].sy = 2 * (get_random_u32() % (h / 2)) + 1; 
	maze[index].ex = -1; 
	maze[index].ey = -1;
	coord_t* stack;
	stack = kmalloc(w * h * sizeof(coord_t), GFP_KERNEL);
	int top = 0;
	stack[top].x = maze[index].sx; 
	stack[top].y = maze[index].sy;
	maze[index].blk[maze[index].sy][maze[index].sx] = 0;
	while(top >= 0)
	{
		int x = stack[top].x;
		int y = stack[top].y;
		top--;
		int dx[] = {0, 0, 2, -2};
		int dy[] = {2, -2, 0, 0};
		for(size_t iteration = 0; iteration < 4; iteration++)
		{
			if(get_random_u32() % 4 == 0) continue;
			int nx = x + dx[iteration];
			int ny = y + dy[iteration];
			if(nx < 0 || nx >= w || ny < 0 || ny >= h) continue;
			if(maze[index].blk[ny][nx] == 0) continue;
			maze[index].blk[ny][nx] = 0;
			int wallx = x + dx[iteration] / 2;
			int wally = y + dy[iteration] / 2;
			maze[index].blk[wally][wallx] = 0;
			top++;
			stack[top].x = nx;
			stack[top].y = ny;
			if(maze[index].ex == -1 || get_random_u32() % 2 == 1)
			{
				maze[index].ex = nx;
				maze[index].ey = ny;
			}
		}
	}
	mazeCurPos[index].x = maze[index].sx;
	mazeCurPos[index].y = maze[index].sy;
	kfree(stack);
	mutex_unlock(&mazeDataMutex);
}

static int mazemod_dev_open(struct inode *i, struct file *f) {
	// printk(KERN_INFO "mazemod: device opened.\n");
	return 0;
}

static int mazemod_dev_close(struct inode *i, struct file *f) {
	// printk(KERN_INFO "mazemod: device closed.\n");
	int procPid = getCurrentPid();
	short mazeIndex = getMazeOwnedByProcess(procPid);
	if(mazeIndex != -1)
	{
		destroyMaze(mazeIndex);
	}
	return 0;
}

static ssize_t mazemod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "mazemod: read %zu bytes @ %llu.\n", len, *off);
	// We may ignore the offset and just return the whole content
	int procPid = getCurrentPid();
	short mazeIndex = getMazeOwnedByProcess(procPid);
	if(mazeIndex == -1)
	{
		return -EBADFD;
	}
	size_t mazeSize = maze[mazeIndex].w * maze[mazeIndex].h;
	size_t returnedBytes = mazeSize;
	if(len < mazeSize)
	{
		returnedBytes = len;
	}
	char *mazeData = kmalloc(mazeSize * sizeof(char), GFP_KERNEL);
	for(size_t i = 0; i < mazeSize; i++)
	{
		size_t row = i / maze[mazeIndex].w;
		size_t col = i % maze[mazeIndex].w;
		mazeData[i] = maze[mazeIndex].blk[row][col];
	}
	long result = copy_to_user(buf, mazeData, returnedBytes);
	kfree(mazeData);
	if(result != 0) {
		return -EBUSY;
	}
	return returnedBytes;
}

static ssize_t mazemod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	int procPid = getCurrentPid();
	short mazeIndex = getMazeOwnedByProcess(procPid);
	if(mazeIndex == -1)
	{
		return -EBADFD;
	}
	if(len % sizeof(coord_t) != 0)
	{
		return -EINVAL;
	}
	size_t moveCount = len / sizeof(coord_t);
	coord_t *moves = kmalloc(moveCount * sizeof(coord_t), GFP_KERNEL);
	long result = copy_from_user(moves, buf, len);
	if(result != 0) {
		return -EBUSY;
	}
	mutex_lock(&mazeDataMutex);
	for(size_t i = 0; i < moveCount; i++)
	{
		if(checkIfAMoveIsLegal(moves[i]) == 0)
		{
			continue;
		}
		moveInAMaze(mazeIndex, moves[i]);
	}
	mutex_unlock(&mazeDataMutex);
	return len;
}

static long mazemod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	switch(cmd){
		case MAZE_CREATE:
		{
			// printk(KERN_INFO "mazemod: MAZE_CREATE.\n");
			coord_t cord;
			long result = copy_from_user(&cord, (coord_t *)arg, sizeof(coord_t));
			if(result != 0) {
				// printk(KERN_INFO "mazemod: copy_from_user failed.\n");
				return -EBUSY;
			}
			if(cord.x < 3 || cord.y < 3 || cord.x > _MAZE_MAXX || cord.y > _MAZE_MAXY)
			{
				return -EINVAL;
			}
			int procPid = getCurrentPid();
			if(getMazeOwnedByProcess(procPid) != -1)
			{
				return -EEXIST;
			}
			int mazeSlot = findAndSetEmptyMazeSlot(procPid);
			if(mazeSlot == -1)
			{
				return -ENOMEM;
			}
			generateRandomMaze(mazeSlot, cord.x, cord.y);
			break;
		}
		case MAZE_RESET:
		{
			// printk(KERN_INFO "mazemod: MAZE_RESET.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			mutex_lock(&mazeDataMutex);
			mazeCurPos[mazeIndex].x = maze[mazeIndex].sx;
			mazeCurPos[mazeIndex].y = maze[mazeIndex].sy;
			mutex_unlock(&mazeDataMutex);
			break;
		}
		case MAZE_DESTROY:
		{
			// printk(KERN_INFO "mazemod: MAZE_DESTROY.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			destroyMaze((size_t)mazeIndex);
			break;
		}
		case MAZE_GETSIZE:
		{
			// printk(KERN_INFO "mazemod: MAZE_GETSIZE.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			coord_t cord;
			cord.x = maze[mazeIndex].w;
			cord.y = maze[mazeIndex].h;
			long result = copy_to_user((coord_t *)arg, &cord, sizeof(coord_t));
			if(result != 0) {
				// printk(KERN_INFO "mazemod: copy_to_user failed.\n");
				return -EBUSY;
			}
			break;
		}
		case MAZE_MOVE:
		{
			// printk(KERN_INFO "mazemod: MAZE_MOVE.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			coord_t cord;
			long result = copy_from_user(&cord, (coord_t *)arg, sizeof(coord_t));
			if(result != 0) {
				// printk(KERN_INFO "mazemod: copy_from_user failed.\n");
				return -EBUSY;
			}
			if(checkIfAMoveIsLegal(cord) == 0)
			{
				break; // spec says to ignore illegal moves
			}
			mutex_lock(&mazeDataMutex);
			moveInAMaze((size_t)mazeIndex, cord);
			mutex_unlock(&mazeDataMutex);
			break;
		}
		case MAZE_GETPOS:
		{
			// printk(KERN_INFO "mazemod: MAZE_GETPOS.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			coord_t cord;
			cord.x = mazeCurPos[mazeIndex].x;
			cord.y = mazeCurPos[mazeIndex].y;
			long result = copy_to_user((coord_t *)arg, &cord, sizeof(coord_t));
			if(result != 0) {
				// printk(KERN_INFO "mazemod: copy_to_user failed.\n");
				return -EBUSY;
			}
			break;
		}
		case MAZE_GETSTART:
		{
			// printk(KERN_INFO "mazemod: MAZE_GETSTART.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			coord_t cord;
			cord.x = maze[mazeIndex].sx;
			cord.y = maze[mazeIndex].sy;
			long result = copy_to_user((coord_t *)arg, &cord, sizeof(coord_t));
			if(result != 0) {
				// printk(KERN_INFO "mazemod: copy_to_user failed.\n");
				return -EBUSY;
			}
			break;
		}
		case MAZE_GETEND:
		{
			// printk(KERN_INFO "mazemod: MAZE_GETEND.\n");
			int procPid = getCurrentPid();
			short mazeIndex = getMazeOwnedByProcess(procPid);
			if(mazeIndex == -1)
			{
				return -ENOENT;
			}
			coord_t cord;
			cord.x = maze[mazeIndex].ex;
			cord.y = maze[mazeIndex].ey;
			long result = copy_to_user((coord_t *)arg, &cord, sizeof(coord_t));
			if(result != 0) {
				// printk(KERN_INFO "mazemod: copy_to_user failed.\n");
				return -EBUSY;
			}
			break;
		}
		default:
		{
			printk(KERN_INFO "mazemod: unknown ioctl cmd=%u.\n", cmd);
			return -EINVAL;
		}
	}
	return 0;
}

static const struct file_operations mazemod_dev_fops = {
	.owner = THIS_MODULE,
	.open = mazemod_dev_open,
	.read = mazemod_dev_read,
	.write = mazemod_dev_write,
	.unlocked_ioctl = mazemod_dev_ioctl,
	.release = mazemod_dev_close
};

static int mazemod_proc_read(struct seq_file *m, void *v) {
	mutex_lock(&mazeDataMutex);
	mutex_lock(&mazeOwnershipMutex);
	for(size_t i = 0; i < _MAZE_MAXUSER; i++)
	{
		printMaze(m, i);
	}
	mutex_unlock(&mazeOwnershipMutex);
	mutex_unlock(&mazeDataMutex);
	return 0;
}

static int mazemod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, mazemod_proc_read, NULL);
}

static const struct proc_ops mazemod_proc_fops = {
	.proc_open = mazemod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *mazemod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init mazemod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = mazemod_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
		goto release_class;
	cdev_init(&c_dev, &mazemod_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("maze", 0, NULL, &mazemod_proc_fops);

	printk(KERN_INFO "mazemod: initialized.\n");

	initDevice();

	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit mazemod_cleanup(void)
{
	remove_proc_entry("maze", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "mazemod: cleaned up.\n");
}

module_init(mazemod_init);
module_exit(mazemod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
