#ifndef _MY_ATTACK_H_
#define _MY_ATTACK_H_

#include "SM3.h"

//SM3³¤¶ÈÀ©Õ¹¹¥»÷
void sm3_extension_attack(unsigned char* append,
	int alen, unsigned char output[32],sm3_context ctx);
#endif