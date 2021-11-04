#ifndef FIXEDPOINT_H
#define FIXEDPOINT_H

typedef int fixed_point;

#define F (1 << 16)

#define div59_60 (59 * F / 60)
#define div1_60 (1 * F / 60)

#define int2fixed(n) ((n)*F)
#define fixed2int(x) ((x) / F)
#define fixed2int_near(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x)-F / 2) / F)
#define add(x, y) ((x) + (y))
#define sub(x, y) ((x) - (y))
#define add_int(x, n) ((x) + (n)*F)
#define sub_int(x, n) ((x) - (n)*F)
#define mul(x, y) (((long long)(x)) * (y) / F)
#define mul_int(x, n) ((x) * (n))
#define div(x, y) (((long long)(x)) * F / (y))
#define div_int(x, n) ((x) / (n))
#endif
