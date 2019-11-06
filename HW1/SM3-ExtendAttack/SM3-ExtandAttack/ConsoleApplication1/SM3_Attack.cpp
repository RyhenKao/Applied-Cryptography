

#include "SM3_Attack.h"
#include "SM3.h"
#include <iostream>
#include <stdio.h>
#include <string.h>

void sm3_extension_attack( unsigned char* append,
	int alen, unsigned char output[32], sm3_context ctx)
{
	unsigned char input[64] = { 0 };
	int i;

	for (i = 0; i < alen; ++i)
	{
		input[i] = append[i];
	}
	input[alen - 1] = 0x00;
	input[alen] = 0x80;

	int len = 512 + alen * 8;
	input[62] = len / 256;
	input[63] = len % 256;


	//直接进行一轮sm3_process
	sm3_process(&ctx, input);

	PUT_ULONG_BE(ctx.state[0], output, 0);
	PUT_ULONG_BE(ctx.state[1], output, 4);
	PUT_ULONG_BE(ctx.state[2], output, 8);
	PUT_ULONG_BE(ctx.state[3], output, 12);
	PUT_ULONG_BE(ctx.state[4], output, 16);
	PUT_ULONG_BE(ctx.state[5], output, 20);
	PUT_ULONG_BE(ctx.state[6], output, 24);
	PUT_ULONG_BE(ctx.state[7], output, 28);
}
