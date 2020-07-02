#ifndef  _BRESENHAM_H_LJ3BQIJF_
#define  _BRESENHAM_H_LJ3BQIJF_

#if defined (__cplusplus)
extern "C" {
#endif

#define BH_CONTINUE 0
#define BH_STOP (-1)

typedef int (*setPixel_cb)(void *, int, int);

struct barg {
	size_t max;
	int idx;
	int (*path)[2];
};

int bresenham_line(int startX, int startY,
		   int endX, int endY,
		   setPixel_cb setPixel,
		   void *data);

size_t bresenham_array(int sx, int sy,
		       int ex, int ey,
		       int (*path)[2],
		       size_t max);


#if defined (__cplusplus)
}	/*end of extern "C"*/
#endif

#endif /* end of include guard:  _BRESENHAM_H_LJ3BQIJF_ */


