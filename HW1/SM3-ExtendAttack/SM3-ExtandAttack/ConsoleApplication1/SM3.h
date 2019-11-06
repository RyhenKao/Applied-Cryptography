/*************************************************************************
	  > File Name: sm3.h
	  > Author:NEWPLAN
	  > E-mail:newplan001@163.com
	  > Created Time: Thu Apr 13 23:55:50 2017
************************************************************************/
#ifndef XYSSL_SM3_H
#define XYSSL_SM3_H


/**
 * \brief          SM3 context structure
 */
typedef struct
{
	unsigned long total[2];     /*!< number of bytes processed  */
	unsigned long state[8];     /*!< intermediate digest state  */
	unsigned char buffer[64];   /*!< data block being processed */

	unsigned char ipad[64];     /*!< HMAC: inner padding        */
	unsigned char opad[64];     /*!< HMAC: outer padding        */

}
sm3_context;

#ifdef __cplusplus
extern "C" {
#endif
	/*
	 * 32-bit integer manipulation macros (big endian)
	 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif
	/**
	 * \brief          SM3 context setup
	 *
	 * \param ctx      context to be initialized
	 */
	void sm3_starts(sm3_context* ctx);

	/**
	 * \brief          SM3 process buffer
	 *
	 * \param ctx      SM3 context
	 * \param input    buffer holding the  data
	 * \param ilen     length of the input data
	 */
	void sm3_update(sm3_context* ctx, unsigned char* input, int ilen);

	/**
	 * \brief          SM3 final digest
	 *
	 * \param ctx      SM3 context
	 */
	void sm3_finish(sm3_context* ctx, unsigned char output[32]);

	/**
	 * \brief          Output = SM3( input buffer )
	 *
	 * \param input    buffer holding the  data
	 * \param ilen     length of the input data
	 * \param output   SM3 checksum result
	 */
	void sm3_process(sm3_context* ctx, unsigned char data[64]);
	void sm3(unsigned char* input, int ilen,
		unsigned char output[32],sm3_context* ctx);

	/**
	 * \brief          Output = SM3( file contents )
	 *
	 * \param path     input file name
	 * \param output   SM3 checksum result
	 *
	 * \return         0 if successful, 1 if fopen failed,
	 *                 or 2 if fread failed
	 */


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
