/* main.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
*
*	2019/01/07
*	对于SM3的长度扩展攻击
*	SM3源代码来自于 https://github.com/NEWPLAN/SMx
*
*/
#include "SM3.h"
#include "SM3_Attack.h"
#include <iostream>
#include <string.h>
#include <stdio.h>

int main()
{
	//原消息
	unsigned char input[] = "Henry";
	int ilen = 6;
	unsigned char output[32];
	int i;
	sm3_context ctx;
	sm3_starts(&ctx);
	printf("Message:\n");
	printf("%s\n", input);
	/*printf("-----------debug-----------\n");
	printf("CTX Init:\n");
	for (i = 0; i < 8; i++) {
		printf("%x\n", ctx.state[i]);
	}
	printf("-------------------------\n");*/


	sm3(input, ilen, output, &ctx);       //对初始信息进行加密
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	printf("-----------debug-----------\n");
	printf("CTX after encrypt\n");
	for (i = 0; i < 8; i++) {
		printf("%x\n", ctx.state[i]);
	}
	printf("-------------------------\n");
	printf("\n");
	unsigned char append_msg[] = "hhhh";
	int alen = 5;
	unsigned char Append_output[32];
	/*不再初始化context，直接使用上一轮的寄存器值做为IV*/
	printf("Append Message:\n");
	printf("%s\n", append_msg);
	printf("-----------debug-----------\n");
	printf("CTX in last encrypt\n");
	for (i = 0; i < 8; i++) {
		printf("%x\n", ctx.state[i]);
	}
	printf("-------------------------\n");
	sm3_extension_attack(append_msg, alen, Append_output, ctx);    //对初始信息进行加密
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", Append_output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");
	printf("-------------------------\n");
	printf("\n");
	/*验证攻击效果*/
	/*生成一个"Henry"+pad+"hhhh"的明文，使用SM3进行加密*/
	unsigned char testInput[] = "Henry\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0hhhh";
	int tlen = 69;
	testInput[ilen] = 0x80;
	testInput[ilen / 64 + 62] = ilen * 8 / 256;
	testInput[ilen / 64 + 63] = ilen * 8 % 256;

	printf("Test Message:\n   ");
	for (i = 0; i < tlen; i++)
	{
		putchar(testInput[i]);
	}
	putchar('\n');

	unsigned char testOutput[32];

	sm3_starts(&ctx);							//初始化context
	/*printf("-----------debug-----------\n");
	printf("CTX Init\n");
	for (i = 0; i < 8; i++) {
		printf("%x\n", ctx.state[i]);
	}
	printf("-------------------------\n");*/
	sm3(testInput, tlen, testOutput, &ctx);
	printf("Encrypted Test Messeage:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", testOutput[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	putchar('\n');
	
	printf("-------Test Result----------\n");
	int flag = 1;
	for (i = 0; i < 32; i++)
	{
		if (testOutput[i] != Append_output[i]) 
		{
			flag = 0;
			break;
		}

	}
	if (flag)
		printf("Attack Succeed!!");
	else
		printf("Attack Failed!!");
	putchar('\n');
	putchar('\n'); 
	putchar('\n');
	putchar('\n');
}


