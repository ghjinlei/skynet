#include <stdlib.h>
#include "bresenham.h"

#define MY_ABS(a) (a) > 0 ? (a) : (-(a))

int bresenham_line(int startX, int startY,
		   int endX, int endY,
		   setPixel_cb setPixel,
		   void *data)
{
	int e2;
	int dx = MY_ABS(endX - startX);
	int sx = startX < endX ? 1 : -1;
	int dy = MY_ABS(endY - startY); 
	int sy = startY < endY ? 1 : -1;
	int err = (dx > dy ? dx : -dy) / 2;

	for(;;) {
		if (setPixel(data, startX, startY) == BH_STOP) {
			return -1;
		}
		if (startX == endX && startY == endY) {
			return 0;
		}
		e2 = err;
		if (e2 >-dx) {
			err -= dy;
			startX += sx;
		}
		if (e2 < dy) {
			err += dx;
			startY += sy;
		}
	}
}

static void bargs_init(struct barg * arg, int (*path)[2], size_t max)
{
	arg->idx = -1;
	arg->max = max;
	arg->path = path;
}

static int put2array(void *data, int x, int y)
{
	struct barg *arg = (struct barg *)data;
	if (arg->idx + 1 >= arg->max) {
		return BH_STOP;
	}
	arg->idx++;
	arg->path[arg->idx][0] = x;
	arg->path[arg->idx][1] = y;
	return BH_CONTINUE;
}

size_t bresenham_array(int sx, int sy,
		       int ex, int ey,
		       int (*path)[2],
		       size_t max)
{
	struct barg arg;
	bargs_init(&arg, path, max);
	bresenham_line(sx, sy, ex, ey, put2array, &arg);
	return arg.idx + 1;
}


