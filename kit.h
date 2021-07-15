/*
	MIT License

	Copyright (c) 2021 Daniele Linguaglossa

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/
#include <windows.h>
#include <wincrypt.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif
#include <corecrt_malloc.h>

#pragma once
#define SAFEAPI
#define UNSAFEAPI
#define KIT_MAX_CLIENTS 1024
#define KIT_MAX_DATA_SIZE 4096
#define KIT_FAIL -1
#define KFALSE 0
#define KTRUE 1
#define KNULL 0
#define KIT_WAIT_MUTEX 3000
#define KIT_MUTEX (kstring*)"Local\\KIT_M"
#define KIT_DEFAULT_ID (kstring *)"Local\\KIT"
#define KIT_DEFAULT_TIMEOUT 5000
#define KSALT (kbinary *)"KIT"
#define KSALT_LENGTH 3
#define DH_KEY_LENGTH 16

#define NIST_B163  1
#define NIST_K163  2
#define NIST_B233  3
#define NIST_K233  4
#define NIST_B283  5
#define NIST_K283  6
#define NIST_B409  7
#define NIST_K409  8
#define NIST_B571  9
#define NIST_K571 10

#ifndef ECC_CURVE
#define ECC_CURVE NIST_B571
#endif

#if defined(ECC_CURVE) && (ECC_CURVE != 0)
#if   (ECC_CURVE == NIST_K163) || (ECC_CURVE == NIST_B163)
#define CURVE_DEGREE       163
#define ECC_PRV_KEY_SIZE   24
#elif (ECC_CURVE == NIST_K233) || (ECC_CURVE == NIST_B233)
#define CURVE_DEGREE       233
#define ECC_PRV_KEY_SIZE   32
#elif (ECC_CURVE == NIST_K283) || (ECC_CURVE == NIST_B283)
#define CURVE_DEGREE       283
#define ECC_PRV_KEY_SIZE   36
#elif (ECC_CURVE == NIST_K409) || (ECC_CURVE == NIST_B409)
#define CURVE_DEGREE       409
#define ECC_PRV_KEY_SIZE   52
#elif (ECC_CURVE == NIST_K571) || (ECC_CURVE == NIST_B571)
#define CURVE_DEGREE       571
#define ECC_PRV_KEY_SIZE   72
#endif
#else
#error Must define a curve to use
#endif

#define ECC_PUB_KEY_SIZE     (2 * ECC_PRV_KEY_SIZE)

#define Nb 4
#define Nk 4
#define Nr 10
#define CBC 1
#define get_sbox_value(num) (sbox[(num)])
#define get_sbox_invert(num) (rsbox[(num)])
#define AES128 1
#define AES_BLOCKLEN 16
#define AES_KEYLEN 16
#define AES_keyExpSize 176
#define multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \


typedef HANDLE khandle;
typedef size_t ksize;
typedef unsigned short kshort;
typedef unsigned int kbool;
typedef char kjson;
typedef char kstring;
typedef const char* kcstring;
typedef unsigned char kbinary;
typedef void* kptr;
typedef unsigned int kuint32;
typedef unsigned char kuint8;
typedef void kvoid;
typedef unsigned long long kuint64;
typedef kuint8 ksharedsecret[20];

typedef union _kuint128 {
	struct {
		kuint64 low;
		kuint64 high;
	};
	unsigned char byte[DH_KEY_LENGTH];
} kuint128;

typedef enum _kit_packet_type {
	KIT_TYPE_BIND = 1,
	KIT_TYPE_CONNECT = 2,
	KIT_TYPE_DISCONNECT = 3,
	KIT_TYPE_ACCEPT = 4,
	KIT_TYPE_HANDSHAKE = 5,
	KIT_TYPE_DATA = 6,
} kit_packet_type;

typedef enum _kit_action {
	KIT_CAN_READ = 1,
	KIT_CAN_WRITE = 2,
	KIT_WAIT = 3,
} kit_action;

typedef enum _kit_data_type {
	KIT_DATA_TEXT = 1,
	KIT_DATA_BINARY = 2,
#ifdef KIT_USE_CJSON
	KIT_DATA_JSON = 3,
#endif
	KIT_DATA_NONE = 4,
} kit_data_type;

typedef enum _kit_packet_flags {
	KIT_FLAG_DEFAULT = 0x2,
	KIT_FLAG_BINDED = 0x4,
	KIT_FLAG_CLOSED = 0x8,
	KIT_FLAG_CONNECTED = 0x10,
	KIT_FLAG_ACCEPTED = 0x20,
	KIT_FLAG_CLIENT_HANDSHAKE = 0x40,
	KIT_FLAG_SERVER_HANDSHAKE = 0x80,
	KIT_FLAG_DISCONNECTED = 0x100,
	KIT_FLAG_RESERVED1 = 0x10000,
	KIT_FLAG_RESERVED2 = 0x20000,
	KIT_FLAG_RESERVED3 = 0x40000,
	KIT_FLAG_RESERVED4 = 0x80000,
} kit_packet_flags;

typedef enum _kit_error {
	KIT_OK = 0,
	KIT_ERR_CREATE_FILE_MAPPING = 0x8000,
	KIT_ERR_MAP_VIEW_OF_FILE = 0x8001,
	KIT_ERR_CREATE_PACKET = 0x8002,
	KIT_ERR_WRITE_MAP = 0x8003,
	KIT_BIND_FAILED = 0x8004,
	KIT_INVALID_PARAMETER = 0x8005,
	KIT_CONNECT_FAILED = 0x8006,
	KIT_MEMORY_READ_ERROR = 0x8007,
	KIT_TIMEOUT_ERROR = 0x8008,
	KIT_KEY_GENERATION_FAILED = 0x8009,
	KIT_PACKET_MISMATCH_CRC32 = 0x800A,
	KIT_SHARED_SECRET_GENERATION_FAILED = 0x800B,
	KIT_KDF_FAILED = 0x800C,
	KIT_INITIALIZATION_FAILED = 0x800D,
	KIT_CRYPTO_ERROR = 0x800E,
	KIT_MEMORY_RESIZE_ERROR = 0x800F,
	KIT_TIMER_ERROR = 0x8010,
	KIT_NO_MORE_SLOT = 0x8011,
} kit_error;

typedef struct _kit_packet_header {
	kit_packet_flags flags;
	kit_packet_type type;
	kuint32 crc32;
	kshort senderid;
	kptr dataptr;
	kuint8 readed;
} kpacket_header, * pkpacket_header;

typedef struct _kit_packet_body {
	ksize length;
	kit_data_type datatype;
	union {
		kbinary bindata[KIT_MAX_DATA_SIZE];
		kstring strdata[KIT_MAX_DATA_SIZE];
#ifdef KIT_USE_CJSON
		kjson jsondata[KIT_MAX_DATA_SIZE];
#endif
	};
} kpacket_body, * pkpacket_body;

typedef struct _kit_packet {
	kpacket_header header;
	kpacket_body body;
} kpacket, * pkpacket;

typedef struct _AES_ctx
{
	kuint8 RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
	kuint8 Iv[AES_BLOCKLEN];
#endif
} AES_ctx;

typedef struct _kit_instance {
	khandle hFile;
	kptr hMap;
	ksize size;
	AES_ctx aes;
	kuint32 id;
	ksharedsecret* sharedSecret;
} kinstance, *pkinstance;

typedef struct _kit_client_info {
	kinstance instance;
	kuint32 clientid;
}kclientinfo, *pkclientinfo;

SAFEAPI kbool kit_init();
SAFEAPI kbool kit_bind(IN kcstring id, OUT pkinstance instance);
SAFEAPI kit_action kit_select(IN pkinstance instance);
SAFEAPI kbool kit_disconnect(IN pkinstance instance);
SAFEAPI pkpacket kit_read(IN pkinstance instance);
SAFEAPI kbool kit_write(IN pkinstance instance, IN kbinary* data, ksize length);
SAFEAPI kbool kit_connect(IN kcstring id, OUT pkinstance instance);
SAFEAPI pkclientinfo kit_listen_and_accept(IN pkinstance instance);
SAFEAPI kuint32 kit_get_error();
SAFEAPI kcstring kit_human_error();
SAFEAPI kvoid kit_notify_disconnect(pkclientinfo clientinfo);
SAFEAPI kbool kit_is_disconnect(pkpacket pkt);
UNSAFEAPI kvoid kit_set_read(IN pkinstance instance);
UNSAFEAPI kvoid kit_decrypt_packet(IN pkinstance instance, IN pkpacket pkt);
UNSAFEAPI kvoid kit_encrypt_packet(IN pkinstance instance, IN pkpacket pkt);
UNSAFEAPI kbool kit_client_handshake(IN pkinstance instance);
UNSAFEAPI kbool kit_read_packet(IN pkinstance instance, OUT pkpacket pkt);
UNSAFEAPI kbool kit_write_packet(IN pkinstance instance, IN pkpacket packet);
UNSAFEAPI kbool kit_make_packet(IN pkinstance instance, IN kit_packet_type ptype, IN kit_data_type dtype, IN kit_packet_flags flags, IN ksize datasize, IN kptr data, OUT pkpacket packet);
UNSAFEAPI kvoid kit_set_error(IN kit_error errid);
UNSAFEAPI kuint32 kit_crc32(IN kptr data, IN ksize datasize);
UNSAFEAPI kbool kit_fill_secure_random(IN kptr buffer, IN ksize size);
UNSAFEAPI kvoid kit_timeout(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired);
UNSAFEAPI kuint8 kit_get_slot();
UNSAFEAPI kvoid kit_free_slot(kuint8 slot);

static khandle kit_global_mutex;
static kuint8 kit_clients[KIT_MAX_CLIENTS] = { 0 };
//static kuint32 kit_client_num;

#ifndef KIT_MULTIPLE_IMPORT
#define KIT_MULTIPLE_IMPORT

#define BITVEC_MARGIN     3
#define BITVEC_NBITS      (CURVE_DEGREE + BITVEC_MARGIN)
#define BITVEC_NWORDS     ((BITVEC_NBITS + 31) / 32)
#define BITVEC_NBYTES     (sizeof(kuint32) * BITVEC_NWORDS)

#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#else
#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))
#endif
#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))
#define SHA1_ROTL(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))
static kuint32 addTemp;
#define SHA1AddLength(context, length)                     \
    (addTemp = (context)->Length_Low,                      \
     (context)->Corrupted =                                \
        (((context)->Length_Low += (length)) < addTemp) && \
        (++(context)->Length_High == 0) ? shaInputTooLong  \
                                        : (context)->Corrupted )

typedef kuint32 bitvec_t[BITVEC_NWORDS];
typedef bitvec_t gf2elem_t;
typedef bitvec_t scalar_t;

static void gf2field_mul(gf2elem_t z, const gf2elem_t x, const gf2elem_t y);

#if defined (ECC_CURVE) && (ECC_CURVE != 0)
#if (ECC_CURVE == NIST_K163)
#define coeff_a  1
#define cofactor 2
/* NIST K-163 */
const gf2elem_t polynomial = { 0x000000c9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008 };
const gf2elem_t coeff_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const gf2elem_t base_x = { 0x5c94eee8, 0xde4e6d5e, 0xaa07d793, 0x7bbc11ac, 0xfe13c053, 0x00000002 };
const gf2elem_t base_y = { 0xccdaa3d9, 0x0536d538, 0x321f2e80, 0x5d38ff58, 0x89070fb0, 0x00000002 };
const scalar_t  base_order = { 0x99f8a5ef, 0xa2e0cc0d, 0x00020108, 0x00000000, 0x00000000, 0x00000004 };
#endif

#if (ECC_CURVE == NIST_B163)
#define coeff_a  1
#define cofactor 2
/* NIST B-163 */
const gf2elem_t polynomial = { 0x000000c9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008 };
const gf2elem_t coeff_b = { 0x4a3205fd, 0x512f7874, 0x1481eb10, 0xb8c953ca, 0x0a601907, 0x00000002 };
const gf2elem_t base_x = { 0xe8343e36, 0xd4994637, 0xa0991168, 0x86a2d57e, 0xf0eba162, 0x00000003 };
const gf2elem_t base_y = { 0x797324f1, 0xb11c5c0c, 0xa2cdd545, 0x71a0094f, 0xd51fbc6c, 0x00000000 };
const scalar_t  base_order = { 0xa4234c33, 0x77e70c12, 0x000292fe, 0x00000000, 0x00000000, 0x00000004 };
#endif

#if (ECC_CURVE == NIST_K233)
#define coeff_a  0
#define cofactor 4
/* NIST K-233 */
const gf2elem_t polynomial = { 0x00000001, 0x00000000, 0x00000400, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200 };
const gf2elem_t coeff_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const gf2elem_t base_x = { 0xefad6126, 0x0a4c9d6e, 0x19c26bf5, 0x149563a4, 0x29f22ff4, 0x7e731af1, 0x32ba853a, 0x00000172 };
const gf2elem_t base_y = { 0x56fae6a3, 0x56e0c110, 0xf18aeb9b, 0x27a8cd9b, 0x555a67c4, 0x19b7f70f, 0x537dece8, 0x000001db };
const scalar_t  base_order = { 0xf173abdf, 0x6efb1ad5, 0xb915bcd4, 0x00069d5b, 0x00000000, 0x00000000, 0x00000000, 0x00000080 };
#endif

#if (ECC_CURVE == NIST_B233)
#define coeff_a  1
#define cofactor 2
/* NIST B-233 */
const gf2elem_t polynomial = { 0x00000001, 0x00000000, 0x00000400, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200 };
const gf2elem_t coeff_b = { 0x7d8f90ad, 0x81fe115f, 0x20e9ce42, 0x213b333b, 0x0923bb58, 0x332c7f8c, 0x647ede6c, 0x00000066 };
const gf2elem_t base_x = { 0x71fd558b, 0xf8f8eb73, 0x391f8b36, 0x5fef65bc, 0x39f1bb75, 0x8313bb21, 0xc9dfcbac, 0x000000fa };
const gf2elem_t base_y = { 0x01f81052, 0x36716f7e, 0xf867a7ca, 0xbf8a0bef, 0xe58528be, 0x03350678, 0x6a08a419, 0x00000100 };
const scalar_t  base_order = { 0x03cfe0d7, 0x22031d26, 0xe72f8a69, 0x0013e974, 0x00000000, 0x00000000, 0x00000000, 0x00000100 };
#endif

#if (ECC_CURVE == NIST_K283)
#define coeff_a  0
#define cofactor 4
/* NIST K-283 */
const gf2elem_t polynomial = { 0x000010a1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
const gf2elem_t coeff_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const gf2elem_t base_x = { 0x58492836, 0xb0c2ac24, 0x16876913, 0x23c1567a, 0x53cd265f, 0x62f188e5, 0x3f1a3b81, 0x78ca4488, 0x0503213f };
const gf2elem_t base_y = { 0x77dd2259, 0x4e341161, 0xe4596236, 0xe8184698, 0xe87e45c0, 0x07e5426f, 0x8d90f95d, 0x0f1c9e31, 0x01ccda38 };
const scalar_t  base_order = { 0x1e163c61, 0x94451e06, 0x265dff7f, 0x2ed07577, 0xffffe9ae, 0xffffffff, 0xffffffff, 0xffffffff, 0x01ffffff };
#endif

#if (ECC_CURVE == NIST_B283)
#define coeff_a  1
#define cofactor 2
/* NIST B-283 */
const gf2elem_t polynomial = { 0x000010a1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
const gf2elem_t coeff_b = { 0x3b79a2f5, 0xf6263e31, 0xa581485a, 0x45309fa2, 0xca97fd76, 0x19a0303f, 0xa5a4af8a, 0xc8b8596d, 0x027b680a };
const gf2elem_t base_x = { 0x86b12053, 0xf8cdbecd, 0x80e2e198, 0x557eac9c, 0x2eed25b8, 0x70b0dfec, 0xe1934f8c, 0x8db7dd90, 0x05f93925 };
const gf2elem_t base_y = { 0xbe8112f4, 0x13f0df45, 0x826779c8, 0x350eddb0, 0x516ff702, 0xb20d02b4, 0xb98fe6d4, 0xfe24141c, 0x03676854 };
const scalar_t  base_order = { 0xefadb307, 0x5b042a7c, 0x938a9016, 0x399660fc, 0xffffef90, 0xffffffff, 0xffffffff, 0xffffffff, 0x03ffffff };
#endif

#if (ECC_CURVE == NIST_K409)
#define coeff_a  0
#define cofactor 4
/* NIST K-409 */
const gf2elem_t polynomial = { 0x00000001, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000 };
const gf2elem_t coeff_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const gf2elem_t base_x = { 0xe9023746, 0xb35540cf, 0xee222eb1, 0xb5aaaa62, 0xc460189e, 0xf9f67cc2, 0x27accfb8, 0xe307c84c, 0x0efd0987, 0x0f718421, 0xad3ab189, 0x658f49c1, 0x0060f05f };
const gf2elem_t base_y = { 0xd8e0286b, 0x5863ec48, 0xaa9ca27a, 0xe9c55215, 0xda5f6c42, 0xe9ea10e3, 0xe6325165, 0x918ea427, 0x3460782f, 0xbf04299c, 0xacba1dac, 0x0b7c4e42, 0x01e36905 };
const scalar_t  base_order = { 0xe01e5fcf, 0x4b5c83b8, 0xe3e7ca5b, 0x557d5ed3, 0x20400ec4, 0x83b2d4ea, 0xfffffe5f, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x007fffff };
#endif

#if (ECC_CURVE == NIST_B409)
#define coeff_a  1
#define cofactor 2
/* NIST B-409 */
const gf2elem_t polynomial = { 0x00000001, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000 };
const gf2elem_t coeff_b = { 0x7b13545f, 0x4f50ae31, 0xd57a55aa, 0x72822f6c, 0xa9a197b2, 0xd6ac27c8, 0x4761fa99, 0xf1f3dd67, 0x7fd6422e, 0x3b7b476b, 0x5c4b9a75, 0xc8ee9feb, 0x0021a5c2 };
const gf2elem_t base_x = { 0xbb7996a7, 0x60794e54, 0x5603aeab, 0x8a118051, 0xdc255a86, 0x34e59703, 0xb01ffe5b, 0xf1771d4d, 0x441cde4a, 0x64756260, 0x496b0c60, 0xd088ddb3, 0x015d4860 };
const gf2elem_t base_y = { 0x0273c706, 0x81c364ba, 0xd2181b36, 0xdf4b4f40, 0x38514f1f, 0x5488d08f, 0x0158aa4f, 0xa7bd198d, 0x7636b9c5, 0x24ed106a, 0x2bbfa783, 0xab6be5f3, 0x0061b1cf };
const scalar_t  base_order = { 0xd9a21173, 0x8164cd37, 0x9e052f83, 0x5fa47c3c, 0xf33307be, 0xaad6a612, 0x000001e2, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x01000000 };
#endif

#if (ECC_CURVE == NIST_K571)
#define coeff_a  0
#define cofactor 4
/* NIST K-571 */
const gf2elem_t polynomial = { 0x00000425, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
const gf2elem_t coeff_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const gf2elem_t base_x = { 0xa01c8972, 0xe2945283, 0x4dca88c7, 0x988b4717, 0x494776fb, 0xbbd1ba39, 0xb4ceb08c, 0x47da304d, 0x93b205e6, 0x43709584, 0x01841ca4, 0x60248048, 0x0012d5d4, 0xac9ca297, 0xf8103fe4, 0x82189631, 0x59923fbc, 0x026eb7a8 };
const gf2elem_t base_y = { 0x3ef1c7a3, 0x01cd4c14, 0x591984f6, 0x320430c8, 0x7ba7af1b, 0xb620b01a, 0xf772aedc, 0x4fbebbb9, 0xac44aea7, 0x9d4979c0, 0x006d8a2c, 0xffc61efc, 0x9f307a54, 0x4dd58cec, 0x3bca9531, 0x4f4aeade, 0x7f4fbf37, 0x0349dc80 };
const scalar_t  base_order = { 0x637c1001, 0x5cfe778f, 0x1e91deb4, 0xe5d63938, 0xb630d84b, 0x917f4138, 0xb391a8db, 0xf19a63e4, 0x131850e1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000 };
#endif

#if (ECC_CURVE == NIST_B571)
#define coeff_a  1
#define cofactor 2
/* NIST B-571 */
const gf2elem_t polynomial = { 0x00000425, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
const gf2elem_t coeff_b = { 0x2955727a, 0x7ffeff7f, 0x39baca0c, 0x520e4de7, 0x78ff12aa, 0x4afd185a, 0x56a66e29, 0x2be7ad67, 0x8efa5933, 0x84ffabbd, 0x4a9a18ad, 0xcd6ba8ce, 0xcb8ceff1, 0x5c6a97ff, 0xb7f3d62f, 0xde297117, 0x2221f295, 0x02f40e7e };
const gf2elem_t base_x = { 0x8eec2d19, 0xe1e7769c, 0xc850d927, 0x4abfa3b4, 0x8614f139, 0x99ae6003, 0x5b67fb14, 0xcdd711a3, 0xf4c0d293, 0xbde53950, 0xdb7b2abd, 0xa5f40fc8, 0x955fa80a, 0x0a93d1d2, 0x0d3cd775, 0x6c16c0d4, 0x34b85629, 0x0303001d };
const gf2elem_t base_y = { 0x1b8ac15b, 0x1a4827af, 0x6e23dd3c, 0x16e2f151, 0x0485c19b, 0xb3531d2f, 0x461bb2a8, 0x6291af8f, 0xbab08a57, 0x84423e43, 0x3921e8a6, 0x1980f853, 0x009cbbca, 0x8c6c27a6, 0xb73d69d7, 0x6dccfffe, 0x42da639b, 0x037bf273 };
const scalar_t  base_order = { 0x2fe84e47, 0x8382e9bb, 0x5174d66e, 0x161de93d, 0xc7dd9ca1, 0x6823851e, 0x08059b18, 0xff559873, 0xe661ce18, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x03ffffff };
#endif
#endif

typedef kuint8 state_t[4][4];
static const kuint8 sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const kuint8 rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif

static const kuint8 Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

enum {
	SHA1_Message_Block_Size = 64, SHA224_Message_Block_Size = 64,
	SHA256_Message_Block_Size = 64, SHA384_Message_Block_Size = 128,
	SHA512_Message_Block_Size = 128,
	USHA_Max_Message_Block_Size = SHA512_Message_Block_Size,

	SHA1HashSize = 20, SHA224HashSize = 28, SHA256HashSize = 32,
	SHA384HashSize = 48, SHA512HashSize = 64,
	USHAMaxHashSize = SHA512HashSize,

	SHA1HashSizeBits = 160, SHA224HashSizeBits = 224,
	SHA256HashSizeBits = 256, SHA384HashSizeBits = 384,
	SHA512HashSizeBits = 512, USHAMaxHashSizeBits = SHA512HashSizeBits
};

enum {
	shaSuccess = 0,
	shaNull,            /* Null pointer parameter */
	shaInputTooLong,    /* input data too long */
	shaStateError,      /* called Input after FinalBits or Result */
	shaBadParam         /* passed a bad parameter */
};

typedef enum SHAversion {
	SHA1, SHA224, SHA256, SHA384, SHA512
} SHAversion;

typedef struct SHA1Context {
	kuint32 Intermediate_Hash[SHA1HashSize / 4];
	kuint32 Length_High;
	kuint32 Length_Low;
	kshort Message_Block_Index;
	kuint8 Message_Block[SHA1_Message_Block_Size];
	int Computed;
	int Corrupted;
} SHA1Context;

typedef struct SHA256Context {
	kuint32 Intermediate_Hash[SHA256HashSize / 4];
	kuint32 Length_High;
	kuint32 Length_Low;
	kshort Message_Block_Index;
	kuint8 Message_Block[SHA256_Message_Block_Size];
	int Computed;
	int Corrupted;
} SHA256Context;

typedef struct SHA512Context {
	kuint64 Intermediate_Hash[SHA512HashSize / 8];
	kuint64 Length_High, Length_Low;
	kshort Message_Block_Index;
	kuint8 Message_Block[SHA512_Message_Block_Size];
	int Computed;
	int Corrupted;
} SHA512Context;

typedef struct SHA256Context SHA224Context;

typedef struct SHA512Context SHA384Context;

typedef struct USHAContext {
	int whichSha;
	union {
		SHA1Context sha1Context;
		SHA224Context sha224Context; SHA256Context sha256Context;
		SHA384Context sha384Context; SHA512Context sha512Context;
	} ctx;
} USHAContext;

typedef struct HMACContext {
	SHAversion whichSha;
	int hashSize;
	int blockSize;
	USHAContext shaContext;
	unsigned char k_opad[USHA_Max_Message_Block_Size];
	int Computed;
	int Corrupted;
} HMACContext;

typedef struct HKDFContext {
	SHAversion whichSha;
	HMACContext hmacContext;
	int hashSize;
	unsigned char prk[USHAMaxHashSize];
	int Computed;
	int Corrupted;
} HKDFContext;

static void key_expansion(kbinary* RoundKey, const kbinary* Key) {
	unsigned i, j, k;
	kuint8 tempa[4];
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
			k = (i - 1) * 4;
			tempa[0] = RoundKey[k + 0];
			tempa[1] = RoundKey[k + 1];
			tempa[2] = RoundKey[k + 2];
			tempa[3] = RoundKey[k + 3];

		}
		if (i % Nk == 0)
		{
			{
				const kuint8 u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}
			{
				tempa[0] = get_sbox_value(tempa[0]);
				tempa[1] = get_sbox_value(tempa[1]);
				tempa[2] = get_sbox_value(tempa[2]);
				tempa[3] = get_sbox_value(tempa[3]);
			}

			tempa[0] = tempa[0] ^ Rcon[i / Nk];
		}
		j = i * 4; k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

void AES_init_ctx(AES_ctx* ctx, const kbinary* key) {
	key_expansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(AES_ctx* ctx, const kbinary* key, const kbinary* iv) {
	key_expansion(ctx->RoundKey, key);
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(AES_ctx* ctx, const kbinary* iv) {
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

static void add_round_key(kuint8 round, state_t* state, const kbinary* RoundKey) {
	kuint8 i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

static void sub_bytes(state_t* state) {
	kuint8 i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = get_sbox_value((*state)[j][i]);
		}
	}
}

static void shift_rows(state_t* state) {
	kuint8 temp;
	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;
	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

static kuint8 xtime(kuint8 x) {
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void mix_columns(state_t* state) {
	kuint8 i;
	kuint8 Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}
}

static void inv_mix_columns(state_t* state) {
	int i;
	kuint8 a, b, c, d;
	for (i = 0; i < 4; ++i)
	{
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
		(*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
		(*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
		(*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
	}
}

static void inv_sub_bytes(state_t* state) {
	kuint8 i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = get_sbox_invert((*state)[j][i]);
		}
	}
}

static void inv_shift_rows(state_t* state) {
	kuint8 temp;
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;
	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}

static void cipher(state_t* state, const kbinary* RoundKey) {
	kuint8 round = 0;
	add_round_key(0, state, RoundKey);
	for (round = 1; ; ++round)
	{
		sub_bytes(state);
		shift_rows(state);
		if (round == Nr) {
			break;
		}
		mix_columns(state);
		add_round_key(round, state, RoundKey);
	}
	add_round_key(Nr, state, RoundKey);
}

static void inv_cipher(state_t* state, const kbinary* RoundKey) {
	kuint8 round = 0;
	add_round_key(Nr, state, RoundKey);
	for (round = (Nr - 1); ; --round)
	{
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(round, state, RoundKey);
		if (round == 0) {
			break;
		}
		inv_mix_columns(state);
	}

}


static void xor_with_iv(kbinary* buf, const kbinary* Iv) {
	kuint8 i;
	for (i = 0; i < AES_BLOCKLEN; ++i)
	{
		buf[i] ^= Iv[i];
	}
}

void AES_CBC_encrypt_buffer(AES_ctx* ctx, kbinary* buf, size_t length) {
	size_t i;
	kbinary* Iv = ctx->Iv;
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		xor_with_iv(buf, Iv);
		cipher((state_t*)buf, ctx->RoundKey);
		Iv = buf;
		buf += AES_BLOCKLEN;
	}
	memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(AES_ctx* ctx, kbinary* buf, size_t length) {
	size_t i;
	kbinary storeNextIv[AES_BLOCKLEN];
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		memcpy(storeNextIv, buf, AES_BLOCKLEN);
		inv_cipher((state_t*)buf, ctx->RoundKey);
		xor_with_iv(buf, ctx->Iv);
		memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
	}

}

ksize AES_pkcs7_pad_value(ksize size) {
	return (16 - (size % 16));
}

ksize AES_pkcs7_pad_size(ksize size) {
	return size + (16 - (size % 16));
}

ksize AES_pkcs7_unpad_size(kbinary* buf, ksize size) {
	return size - buf[size - 1];
}

kbinary* AES_pkcs7_pad(kbinary* buf, ksize size) {
	ksize pad_size = AES_pkcs7_pad_size(size);
	kbinary* padded = (kbinary*)malloc(pad_size + 1);
	ksize pad_value = AES_pkcs7_pad_value(size);
	memset(padded, 0, pad_size + 1);
	memcpy(padded, buf, size);
	for (int i = 0; i < pad_value; i++)
		padded[size + i] = (kbinary)pad_value;
	return padded;
}

kbinary* AES_pkcs7_unpad(kbinary* buf, ksize size) {
	ksize pad_value = buf[size - 1];
	kbinary* unpadded = (kbinary*)malloc((size - pad_value) + 1);
	memset(unpadded, 0, (size - pad_value) + 1);
	memcpy(unpadded, buf, size - pad_value);
	return unpadded;
}

static void SHA1_process_message_block(SHA1Context* context) {
	const kuint32 K[4] = {
		0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
	};
	int        t;               /* Loop counter */
	kuint32   temp;            /* Temporary word value */
	kuint32   W[80];           /* Word sequence */
	kuint32   A, B, C, D, E;   /* Word buffers */
	for (t = 0; t < 16; t++) {
		W[t] = ((kuint32)context->Message_Block[t * 4]) << 24;
		W[t] |= ((kuint32)context->Message_Block[t * 4 + 1]) << 16;
		W[t] |= ((kuint32)context->Message_Block[t * 4 + 2]) << 8;
		W[t] |= ((kuint32)context->Message_Block[t * 4 + 3]);
	}
	for (t = 16; t < 80; t++)
		W[t] = SHA1_ROTL(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	for (t = 0; t < 20; t++) {
		temp = SHA1_ROTL(5, A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}
	for (t = 20; t < 40; t++) {
		temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}
	for (t = 40; t < 60; t++) {
		temp = SHA1_ROTL(5, A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}
	for (t = 60; t < 80; t++) {
		temp = SHA1_ROTL(5, A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1_ROTL(30, B);
		B = A;
		A = temp;
	}
	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;
	context->Message_Block_Index = 0;
}


static void SHA1_pad_message(SHA1Context* context, kuint8 Pad_Byte) {
	if (context->Message_Block_Index >= (SHA1_Message_Block_Size - 8)) {
		context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
		while (context->Message_Block_Index < SHA1_Message_Block_Size)
			context->Message_Block[context->Message_Block_Index++] = 0;
		SHA1_process_message_block(context);
	}
	else
		context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
	while (context->Message_Block_Index < (SHA1_Message_Block_Size - 8))
		context->Message_Block[context->Message_Block_Index++] = 0;
	context->Message_Block[56] = (kuint8)(context->Length_High >> 24);
	context->Message_Block[57] = (kuint8)(context->Length_High >> 16);
	context->Message_Block[58] = (kuint8)(context->Length_High >> 8);
	context->Message_Block[59] = (kuint8)(context->Length_High);
	context->Message_Block[60] = (kuint8)(context->Length_Low >> 24);
	context->Message_Block[61] = (kuint8)(context->Length_Low >> 16);
	context->Message_Block[62] = (kuint8)(context->Length_Low >> 8);
	context->Message_Block[63] = (kuint8)(context->Length_Low);
	SHA1_process_message_block(context);
}

static void SHA1_finalize(SHA1Context* context, kuint8 Pad_Byte) {
	int i;
	SHA1_pad_message(context, Pad_Byte);
	for (i = 0; i < SHA1_Message_Block_Size; ++i)
		context->Message_Block[i] = 0;
	context->Length_High = 0;
	context->Length_Low = 0;
	context->Computed = 1;
}

int SHA1_result(SHA1Context* context, kuint8 Message_Digest[SHA1HashSize]) {
	int i;
	if (!context) return shaNull;
	if (!Message_Digest) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (!context->Computed)
		SHA1_finalize(context, 0x80);
	for (i = 0; i < SHA1HashSize; ++i)
		Message_Digest[i] = (kuint8)(context->Intermediate_Hash[i >> 2]
			>> (8 * (3 - (i & 0x03))));
	return shaSuccess;
}

int SHA1_final_bits(SHA1Context* context, kuint8 message_bits, unsigned int length) {
	static kuint8 masks[8] = { 0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };
	static kuint8 markbit[8] = { 0x80, 0x40, 0x20, 0x10,0x08, 0x04, 0x02, 0x01 };
	if (!context) return shaNull;
	if (!length) return shaSuccess;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	if (length >= 8) return context->Corrupted = shaBadParam;
	SHA1AddLength(context, length);
	SHA1_finalize(context, (kuint8)((message_bits & masks[length]) | markbit[length]));
	return context->Corrupted;
}

int SHA1_input(SHA1Context* context, kuint8* message_array, unsigned length) {
	if (!context) return shaNull;
	if (!length) return shaSuccess;
	if (!message_array) return shaNull;
	if (context->Computed) return context->Corrupted = shaStateError;
	if (context->Corrupted) return context->Corrupted;
	while (length--) {
		context->Message_Block[context->Message_Block_Index++] =
			*message_array;
		if ((SHA1AddLength(context, 8) == shaSuccess) &&
			(context->Message_Block_Index == SHA1_Message_Block_Size))
			SHA1_process_message_block(context);

		message_array++;
	}
	return context->Corrupted;
}

int SHA1_reset(SHA1Context* context) {
	if (!context) return shaNull;
	context->Length_High = context->Length_Low = 0;
	context->Message_Block_Index = 0;
	context->Intermediate_Hash[0] = 0x67452301;
	context->Intermediate_Hash[1] = 0xEFCDAB89;
	context->Intermediate_Hash[2] = 0x98BADCFE;
	context->Intermediate_Hash[3] = 0x10325476;
	context->Intermediate_Hash[4] = 0xC3D2E1F0;
	context->Computed = 0;
	context->Corrupted = shaSuccess;
	return shaSuccess;
}

int USHA_hash_size(enum SHAversion whichSha) {
	switch (whichSha) {
	case SHA1:   return SHA1HashSize;
	case SHA224: return SHA224HashSize;
	case SHA256: return SHA256HashSize;
	case SHA384: return SHA384HashSize;
	default:
	case SHA512: return SHA512HashSize;
	}
}

int USHA_block_size(enum SHAversion whichSha) {
	switch (whichSha) {
	case SHA1:   return SHA1_Message_Block_Size;
	case SHA224: return SHA224_Message_Block_Size;
	case SHA256: return SHA256_Message_Block_Size;
	case SHA384: return SHA384_Message_Block_Size;
	default:
	case SHA512: return SHA512_Message_Block_Size;
	}
}

int USHA_result(USHAContext* context, kuint8 Message_Digest[USHAMaxHashSize]) {
	if (!context) return shaNull;
	switch (context->whichSha) {
	case SHA1:
		return SHA1_result((SHA1Context*)&context->ctx, Message_Digest);
	default: return shaBadParam;
	}
}

int USHA_final_bits(USHAContext* context, kuint8 bits, kuint32 bit_count) {
	if (!context) return shaNull;
	switch (context->whichSha) {
	case SHA1:
		return SHA1_final_bits((SHA1Context*)&context->ctx, bits, bit_count);
	default: return shaBadParam;
	}
}

int USHA_input(USHAContext* context, kuint8* bytes, kuint32 bytecount) {
	if (!context) return shaNull;
	switch (context->whichSha) {
	case SHA1:
		return SHA1_input((SHA1Context*)&context->ctx, bytes, bytecount);
	default: return shaBadParam;
	}
}

int USHA_reset(USHAContext* context, enum SHAversion whichSha) {
	if (!context) return shaNull;
	context->whichSha = whichSha;
	switch (whichSha) {
	case SHA1:   return SHA1_reset((SHA1Context*)&context->ctx);
	default: return shaBadParam;
	}
}

int hmac_result(HMACContext* context, kuint8* digest)
{
	int ret;
	if (!context) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	ret =
		USHA_result(&context->shaContext, digest) ||
		USHA_reset(&context->shaContext, context->whichSha) ||
		USHA_input(&context->shaContext, context->k_opad, context->blockSize) ||
		USHA_input(&context->shaContext, digest, context->hashSize) ||
		USHA_result(&context->shaContext, digest);
	context->Computed = 1;
	return context->Corrupted = ret;
}

int hmac_final_bits(HMACContext* context, kuint8 bits, kuint32 bit_count) {
	if (!context) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	return context->Corrupted = USHA_final_bits(&context->shaContext, bits, bit_count);
}

int hmac_input(HMACContext* context, kbinary* text, int text_len) {
	if (!context) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	return context->Corrupted = USHA_input(&context->shaContext, text, text_len);
}

int hmac_reset(HMACContext* context, enum SHAversion whichSha, kbinary* key, int key_len) {
	int i, blocksize, hashsize, ret;
	kbinary k_ipad[USHA_Max_Message_Block_Size];
	kbinary tempkey[USHAMaxHashSize];
	if (!context) return shaNull;
	context->Computed = 0;
	context->Corrupted = shaSuccess;
	blocksize = context->blockSize = USHA_block_size(whichSha);
	hashsize = context->hashSize = USHA_hash_size(whichSha);
	context->whichSha = whichSha;
	if (key_len > blocksize) {
		USHAContext tcontext;
		int err = USHA_reset(&tcontext, whichSha) ||
			USHA_input(&tcontext, key, key_len) ||
			USHA_result(&tcontext, tempkey);
		if (err != shaSuccess) return err;

		key = tempkey;
		key_len = hashsize;
	}
	for (i = 0; i < key_len; i++) {
		k_ipad[i] = key[i] ^ 0x36;
		context->k_opad[i] = key[i] ^ 0x5c;
	}
	for (; i < blocksize; i++) {
		k_ipad[i] = 0x36;
		context->k_opad[i] = 0x5c;
	}
	ret = USHA_reset(&context->shaContext, whichSha) || USHA_input(&context->shaContext, k_ipad, blocksize);
	return context->Corrupted = ret;
}

int hmac(SHAversion whichSha, kbinary* message_array, int length, kbinary* key, int key_len, kuint8 digest[USHAMaxHashSize]) {
	HMACContext context;
	return hmac_reset(&context, whichSha, key, key_len) || hmac_input(&context, message_array, length) || hmac_result(&context, digest);
}

int hkdf_expand(SHAversion whichSha, const kuint8 prk[], int prk_len, kbinary* info, int info_len, kuint8 okm[], int okm_len) {
	int hash_len, N;
	kuint8 T[USHAMaxHashSize];
	int Tlen, where, i;
	if (info == 0) {
		info = (kbinary*)"";
		info_len = 0;
	}
	else if (info_len < 0) {
		return shaBadParam;
	}
	if (okm_len <= 0) return shaBadParam;
	if (!okm) return shaBadParam;
	hash_len = USHA_hash_size(whichSha);
	if (prk_len < hash_len) return shaBadParam;
	N = okm_len / hash_len;
	if ((okm_len % hash_len) != 0) N++;
	if (N > 255) return shaBadParam;
	Tlen = 0;
	where = 0;
	for (i = 1; i <= N; i++) {
		HMACContext context;
		unsigned char c = i;
		int ret = hmac_reset(&context, whichSha, (kbinary*)prk, prk_len) ||
			hmac_input(&context, T, Tlen) ||
			hmac_input(&context, info, info_len) ||
			hmac_input(&context, &c, 1) ||
			hmac_result(&context, T);
		if (ret != shaSuccess) return ret;
		memcpy(okm + where, T,
			(i != N) ? hash_len : (okm_len - where));
		where += hash_len;
		Tlen = hash_len;
	}
	return shaSuccess;
}

int hkdf_result(HKDFContext* context, kuint8 prk[USHAMaxHashSize], kbinary* info, int info_len, kuint8 okm[], int okm_len) {
	kuint8 prkbuf[USHAMaxHashSize];
	int ret;
	if (!context) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	if (!okm) return context->Corrupted = shaBadParam;
	if (!prk) prk = prkbuf;
	ret = hmac_result(&context->hmacContext, prk) || hkdf_expand(context->whichSha, prk, context->hashSize, info, info_len, okm, okm_len);
	context->Computed = 1;
	return context->Corrupted = ret;
}

int hkdf_final_bits(HKDFContext* context, kuint8 ikm_bits, kuint32 ikm_bit_count) {
	if (!context) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	return hmac_final_bits(&context->hmacContext, ikm_bits, ikm_bit_count);
}

int hkdf_input(HKDFContext* context, kbinary* ikm, int ikm_len) {
	if (!context) return shaNull;
	if (context->Corrupted) return context->Corrupted;
	if (context->Computed) return context->Corrupted = shaStateError;
	return hmac_input(&context->hmacContext, ikm, ikm_len);
}

int hkdf_reset(HKDFContext* context, enum SHAversion whichSha, kbinary* salt, int salt_len) {
	unsigned char nullSalt[USHAMaxHashSize];
	if (!context) return shaNull;
	context->whichSha = whichSha;
	context->hashSize = USHA_hash_size(whichSha);
	if (salt == 0) {
		salt = nullSalt;
		salt_len = context->hashSize;
		memset(nullSalt, '\0', salt_len);
	}
	return hmac_reset(&context->hmacContext, whichSha, salt, salt_len);
}

int hkdf_extract(SHAversion whichSha, kbinary* salt, int salt_len, kbinary* ikm, int ikm_len, kuint8 prk[USHAMaxHashSize]) {
	unsigned char nullSalt[USHAMaxHashSize];
	if (salt == 0) {
		salt = nullSalt;
		salt_len = USHA_hash_size(whichSha);
		memset(nullSalt, '\0', salt_len);
	}
	else if (salt_len < 0) {
		return shaBadParam;
	}
	return hmac(whichSha, ikm, ikm_len, salt, salt_len, prk);
}

int hkdf(SHAversion whichSha, kbinary* salt, int salt_len, kbinary* ikm, int ikm_len, kbinary* info, int info_len, kuint8 okm[], int okm_len) {
	kuint8 prk[USHAMaxHashSize];
	return hkdf_extract(whichSha, salt, salt_len, ikm, ikm_len, prk) || hkdf_expand(whichSha, prk, USHA_hash_size(whichSha), info, info_len, okm, okm_len);
}


typedef union {
	kptr     object;
	HCRYPTPROV hCryptProv;
}
CSPRNG_TYPE;

CSPRNG_TYPE* csprng_create() {
	CSPRNG_TYPE* csprng = (CSPRNG_TYPE*)malloc(sizeof(CSPRNG_TYPE));
	memset(csprng, 0, sizeof(CSPRNG_TYPE));
	if (csprng != NULL) {
		csprng->object = NULL;
		if (!CryptAcquireContextA(&csprng->hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
			csprng->hCryptProv = 0;
		return csprng;
	}
	return KNULL;
}

kbool csprng_delete(CSPRNG_TYPE* c) {
	if (CryptReleaseContext(c->hCryptProv, 0)) {
		free(c);
		return KTRUE;
	}
	return KFALSE;
}

int csprng_get(kptr object, void* dest, unsigned long long size) {
	unsigned long long n;

	CSPRNG_TYPE csprng;
	csprng.object = object;
	if (!csprng.hCryptProv) return 0;

	n = size >> 30;
	while (n--)
		if (!CryptGenRandom(csprng.hCryptProv, 1UL << 30, (BYTE*)dest)) return 0;

	return !!CryptGenRandom(csprng.hCryptProv, size & ((1ULL << 30) - 1), (BYTE*)dest);
}

long csprng_get_int(kptr object) {
	long result;
	return csprng_get(object, &result, sizeof(result)) ? result : 0;
}

static int bitvec_get_bit(const bitvec_t x, const kuint32 idx) {
	return ((x[idx / 32U] >> (idx & 31U) & 1U));
}

static void bitvec_clr_bit(bitvec_t x, const kuint32 idx) {
	x[idx / 32U] &= ~(1U << (idx & 31U));
}

static void bitvec_copy(bitvec_t x, const bitvec_t y) {
	int i;
	for (i = 0; i < BITVEC_NWORDS; ++i)
	{
		x[i] = y[i];
	}
}

static void bitvec_swap(bitvec_t x, bitvec_t y) {
	bitvec_t tmp;
	bitvec_copy(tmp, x);
	bitvec_copy(x, y);
	bitvec_copy(y, tmp);
}

/* fast version of equality test */
static int bitvec_equal(const bitvec_t x, const bitvec_t y) {
	int i;
	for (i = 0; i < BITVEC_NWORDS; ++i)
	{
		if (x[i] != y[i])
		{
			return 0;
		}
	}
	return 1;
}

static void bitvec_set_zero(bitvec_t x) {
	int i;
	for (i = 0; i < BITVEC_NWORDS; ++i)
	{
		x[i] = 0;
	}
}

static int bitvec_is_zero(const bitvec_t x) {
	kuint32 i = 0;
	while (i < BITVEC_NWORDS)
	{
		if (x[i] != 0)
		{
			break;
		}
		i += 1;
	}
	return (i == BITVEC_NWORDS);
}

static int bitvec_degree(const bitvec_t x) {
	int i = BITVEC_NWORDS * 32;
	x += BITVEC_NWORDS;
	while ((i > 0)
		&& (*(--x)) == 0)
	{
		i -= 32;
	}
	if (i != 0)
	{
		kuint32 u32mask = ((kuint32)1 << 31);
		while (((*x) & u32mask) == 0)
		{
			u32mask >>= 1;
			i -= 1;
		}
	}
	return i;
}

static void bitvec_lshift(bitvec_t x, const bitvec_t y, int nbits) {
	int nwords = (nbits / 32);
	int i, j;
	for (i = 0; i < nwords; ++i)
	{
		x[i] = 0;
	}
	j = 0;
	while (i < BITVEC_NWORDS)
	{
		x[i] = y[j];
		i += 1;
		j += 1;
	}
	nbits &= 31;
	if (nbits != 0)
	{
		int i;
		for (i = (BITVEC_NWORDS - 1); i > 0; --i)
		{
			x[i] = (x[i] << nbits) | (x[i - 1] >> (32 - nbits));
		}
		x[0] <<= nbits;
	}
}


static void gf2field_set_one(gf2elem_t x) {
	x[0] = 1;
	int i;
	for (i = 1; i < BITVEC_NWORDS; ++i)
	{
		x[i] = 0;
	}
}

static int gf2field_is_one(const gf2elem_t x) {
	if (x[0] != 1)
	{
		return 0;
	}
	int i;
	for (i = 1; i < BITVEC_NWORDS; ++i)
	{
		if (x[i] != 0)
		{
			break;
		}
	}
	return (i == BITVEC_NWORDS);
}

static void gf2field_add(gf2elem_t z, const gf2elem_t x, const gf2elem_t y) {
	int i;
	for (i = 0; i < BITVEC_NWORDS; ++i)
	{
		z[i] = (x[i] ^ y[i]);
	}
}

static void gf2field_inc(gf2elem_t x) {
	x[0] ^= 1;
}

static void gf2field_mul(gf2elem_t z, const gf2elem_t x, const gf2elem_t y) {
	int i;
	gf2elem_t tmp;
	bitvec_copy(tmp, x);
	if (bitvec_get_bit(y, 0) != 0)
	{
		bitvec_copy(z, x);
	}
	else
	{
		bitvec_set_zero(z);
	}
	for (i = 1; i < CURVE_DEGREE; ++i)
	{
		bitvec_lshift(tmp, tmp, 1);
		if (bitvec_get_bit(tmp, CURVE_DEGREE))
		{
			gf2field_add(tmp, tmp, polynomial);
		}
		if (bitvec_get_bit(y, i))
		{
			gf2field_add(z, z, tmp);
		}
	}
}

static void gf2field_inv(gf2elem_t z, const gf2elem_t x) {
	gf2elem_t u, v, g, h;
	int i;
	bitvec_copy(u, x);
	bitvec_copy(v, polynomial);
	bitvec_set_zero(g);
	gf2field_set_one(z);
	while (!gf2field_is_one(u))
	{
		i = (bitvec_degree(u) - bitvec_degree(v));
		if (i < 0)
		{
			bitvec_swap(u, v);
			bitvec_swap(g, z);
			i = -i;
		}
		bitvec_lshift(h, v, i);
		gf2field_add(u, u, h);
		bitvec_lshift(h, g, i);
		gf2field_add(z, z, h);
	}
}

static void gf2point_copy(gf2elem_t x1, gf2elem_t y1, const gf2elem_t x2, const gf2elem_t y2) {
	bitvec_copy(x1, x2);
	bitvec_copy(y1, y2);
}

static void gf2point_set_zero(gf2elem_t x, gf2elem_t y) {
	bitvec_set_zero(x);
	bitvec_set_zero(y);
}

static int gf2point_is_zero(const gf2elem_t x, const gf2elem_t y) {
	return (bitvec_is_zero(x) && bitvec_is_zero(y));
}

static void gf2point_double(gf2elem_t x, gf2elem_t y) {
	if (bitvec_is_zero(x))
	{
		bitvec_set_zero(y);
	}
	else
	{
		gf2elem_t l;
		gf2field_inv(l, x);
		gf2field_mul(l, l, y);
		gf2field_add(l, l, x);
		gf2field_mul(y, x, x);
		gf2field_mul(x, l, l);
#if (coeff_a == 1)
		gf2field_inc(l);
#endif
		gf2field_add(x, x, l);
		gf2field_mul(l, l, x);
		gf2field_add(y, y, l);
	}
}

static void gf2point_add(gf2elem_t x1, gf2elem_t y1, const gf2elem_t x2, const gf2elem_t y2) {
	if (!gf2point_is_zero(x2, y2))
	{
		if (gf2point_is_zero(x1, y1))
		{
			gf2point_copy(x1, y1, x2, y2);
		}
		else
		{
			if (bitvec_equal(x1, x2))
			{
				if (bitvec_equal(y1, y2))
				{
					gf2point_double(x1, y1);
				}
				else
				{
					gf2point_set_zero(x1, y1);
				}
			}
			else
			{
				gf2elem_t a, b, c, d;
				gf2field_add(a, y1, y2);
				gf2field_add(b, x1, x2);
				gf2field_inv(c, b);
				gf2field_mul(c, c, a);
				gf2field_mul(d, c, c);
				gf2field_add(d, d, c);
				gf2field_add(d, d, b);
#if (coeff_a == 1)
				gf2field_inc(d);
#endif
				gf2field_add(x1, x1, d);
				gf2field_mul(a, x1, c);
				gf2field_add(a, a, d);
				gf2field_add(y1, y1, a);
				bitvec_copy(x1, d);
			}
		}
	}
}


static void gf2point_mul(gf2elem_t x, gf2elem_t y, const scalar_t exp) {
	gf2elem_t tmpx, tmpy;
	gf2elem_t dummyx, dummyy;
	int i;
	int nbits = bitvec_degree(exp);

	gf2point_set_zero(tmpx, tmpy);
	gf2point_set_zero(dummyx, dummyy);

	for (i = (nbits - 1); i >= 0; --i)
	{
		gf2point_double(tmpx, tmpy);
		if (bitvec_get_bit(exp, i))
		{
			gf2point_add(tmpx, tmpy, x, y);
		}
		else
		{
			gf2point_add(tmpx, tmpy, dummyx, dummyy);
		}
	}
	gf2point_copy(x, y, tmpx, tmpy);
}

static int gf2point_on_curve(const gf2elem_t x, const gf2elem_t y) {
	gf2elem_t a, b;

	if (gf2point_is_zero(x, y))
	{
		return 1;
	}
	else
	{
		gf2field_mul(a, x, x);
#if (coeff_a == 0)
		gf2field_mul(a, a, x);
#else
		gf2field_mul(b, a, x);
		gf2field_add(a, a, b);
#endif
		gf2field_add(a, a, coeff_b);
		gf2field_mul(b, y, y);
		gf2field_add(a, a, b);
		gf2field_mul(b, x, y);

		return bitvec_equal(a, b);
	}
}


int ecdh_generate_keys(kuint8* public_key, kuint8* private_key) {
	gf2point_copy((kuint32*)public_key, (kuint32*)(public_key + BITVEC_NBYTES), base_x, base_y);
	if (bitvec_degree((kuint32*)private_key) < (CURVE_DEGREE / 2))
	{
		return 0;
	}
	else
	{
		int nbits = bitvec_degree(base_order);
		int i;
		for (i = (nbits - 1); i < (BITVEC_NWORDS * 32); ++i)
		{
			bitvec_clr_bit((kuint32*)private_key, i);
		}
		gf2point_mul((kuint32*)public_key, (kuint32*)(public_key + BITVEC_NBYTES), (kuint32*)private_key);
		return 1;
	}
}


int ecdh_shared_secret(const kuint8* private_key, const kuint8* others_pub, kuint8* output) {
	if (!gf2point_is_zero((kuint32*)others_pub, (kuint32*)(others_pub + BITVEC_NBYTES))
		&& gf2point_on_curve((kuint32*)others_pub, (kuint32*)(others_pub + BITVEC_NBYTES)))
	{
		unsigned int i;
		for (i = 0; i < (BITVEC_NBYTES * 2); ++i)
		{
			output[i] = others_pub[i];
		}
		gf2point_mul((kuint32*)output, (kuint32*)(output + BITVEC_NBYTES), (const kuint32*)private_key);
		return 1;
	}
	else
	{
		return 0;
	}
}

const kuint32 crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

kbool kit_is_disconnect(pkpacket pkt) {
	if (pkt->header.type == KIT_TYPE_DISCONNECT && pkt->header.flags == KIT_FLAG_DISCONNECTED) {
		free(pkt);
		return KTRUE;
	}
	return KFALSE;
}

kvoid kit_notify_disconnect(pkclientinfo clientinfo) {
	kit_free_slot(clientinfo->clientid);
	memset(clientinfo->instance.hMap, 0, sizeof(kpacket));
}

kuint32 kit_crc32(IN kptr data, IN ksize datasize) {
	const kbinary* p = (kbinary*)data;
	kuint32 crc;
	crc = ~0U;
	while (datasize--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	return crc ^ ~0U;
}

kbool kit_make_packet(IN pkinstance instance, IN kit_packet_type ptype, IN kit_data_type dtype, IN kit_packet_flags flags, IN ksize datasize, IN kptr data, OUT pkpacket packet) {
	memset(packet, 0, sizeof(kpacket));
	packet->header.type = ptype;
	if (flags & KIT_FLAG_RESERVED1 || flags & KIT_FLAG_RESERVED2 || flags & KIT_FLAG_RESERVED3 || flags & KIT_FLAG_RESERVED4) {
		kit_set_error(KIT_ERR_CREATE_PACKET);
		return KFALSE;
	}
	packet->header.flags = (kit_packet_flags)(flags - (flags & ~(KIT_FLAG_DEFAULT | KIT_FLAG_BINDED | KIT_FLAG_CLOSED | KIT_FLAG_CONNECTED | KIT_FLAG_ACCEPTED | KIT_FLAG_CLIENT_HANDSHAKE | KIT_FLAG_SERVER_HANDSHAKE | KIT_FLAG_DISCONNECTED)));
	if (dtype != KIT_DATA_NONE) {
		if (datasize > sizeof(packet->body.bindata)) {
			datasize = sizeof(packet->body.bindata);
		}
		packet->body.length = datasize;
		packet->body.datatype = dtype;
		packet->header.dataptr = (kptr)memcpy(packet->body.bindata, data, datasize);
		packet->header.crc32 = kit_crc32(data, datasize);
		packet->header.readed = 0;
	}
	else {
		packet->header.crc32 = -1;
	}
	packet->header.senderid = instance->id;
	kit_set_error(KIT_OK);
	return KTRUE;
}

kbool kit_write_packet(IN pkinstance instance, IN pkpacket packet) {
	kuint32 mutex_status = WaitForSingleObject(kit_global_mutex, KIT_WAIT_MUTEX);
	kbool ret;
	switch (mutex_status) {
	case WAIT_OBJECT_0:
		ret = (kbool)(memcpy(instance->hMap, packet, sizeof(kpacket)) > 0);
		if (!ret) {
			kit_set_error(KIT_ERR_WRITE_MAP);
		}
		ret = ret && FlushViewOfFile(instance->hMap, instance->size);
		if (ret)
			kit_set_error(KIT_OK);
		ReleaseMutex(kit_global_mutex);
		return ret;
	case WAIT_TIMEOUT:
	default:
		kit_set_error(KIT_ERR_WRITE_MAP);
		return KFALSE;
		break;
	}
}

kbool kit_bind(IN kcstring id, OUT pkinstance instance) {
	khandle hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_RESERVE, 0, sizeof(kpacket) * KIT_MAX_CLIENTS, id);
	if (!hFile) {
		kit_set_error(KIT_ERR_CREATE_FILE_MAPPING);
		return KFALSE;
	}
	kptr hMap = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (!hMap) {
		kit_set_error(KIT_ERR_MAP_VIEW_OF_FILE);
		return KFALSE;
	}
	instance->hFile = hFile;
	instance->hMap = hMap;
	instance->size = sizeof(kpacket);
	instance->sharedSecret = (ksharedsecret*)malloc(sizeof(ksharedsecret) * KIT_MAX_CLIENTS);
	instance->id = 0;
	kit_clients[instance->id] = 1;
	memset(instance->sharedSecret, 0, sizeof(ksharedsecret) * KIT_MAX_CLIENTS);
	kpacket pkt;
	if (!VirtualAlloc(instance->hMap, sizeof(kpacket), MEM_COMMIT, PAGE_READWRITE)) {
		kit_set_error(KIT_MEMORY_RESIZE_ERROR);
		return KFALSE;
	}
	if (!kit_make_packet(instance, KIT_TYPE_BIND, KIT_DATA_NONE, KIT_FLAG_BINDED, 0, 0, &pkt) == KTRUE) {
		kit_set_error(KIT_BIND_FAILED);
		return KFALSE;
	}
	if (!kit_write_packet(instance, &pkt)) {
		return KFALSE;
	}
	kit_set_error(KIT_OK);
	return KTRUE;
}

kbool kit_read_packet(IN pkinstance instance, OUT pkpacket pkt) {
	kuint32 mutex_status = WaitForSingleObject(kit_global_mutex, KIT_WAIT_MUTEX);
	switch (mutex_status) {
	case WAIT_OBJECT_0:
		memset(pkt, 0, sizeof(kpacket));
		if (memcpy(pkt, instance->hMap, sizeof(kpacket))) {
			if (pkt->header.type == KIT_TYPE_HANDSHAKE || pkt->header.type == KIT_TYPE_DATA) {
				if (pkt->body.datatype != KIT_DATA_NONE) {
					if (pkt->header.crc32 != kit_crc32(pkt->body.bindata, pkt->body.length)) {
						ReleaseMutex(kit_global_mutex);
						kit_set_error(KIT_PACKET_MISMATCH_CRC32);
						return KFALSE;
					}
				}
			}
			ReleaseMutex(kit_global_mutex);
			kit_set_error(KIT_OK);
			return KTRUE;
		}
	case WAIT_TIMEOUT:
	default:
		kit_set_error(KIT_MEMORY_READ_ERROR);
		return KFALSE;
	}
}

kvoid kit_timeout(IN PVOID lpParameter, IN BOOLEAN TimerOrWaitFired) {
	if (TimerOrWaitFired) {
		*(kbool*)lpParameter = KTRUE;
	}
}

kbool kit_connect(IN kcstring id, OUT pkinstance instance) {
	khandle hFile = OpenFileMappingA(FILE_MAP_WRITE | FILE_MAP_READ, FALSE, id);
	if (!hFile) {
		kit_set_error(KIT_CONNECT_FAILED);
		return KFALSE;
	}
	kptr hMap = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (!hMap) {
		kit_set_error(KIT_ERR_MAP_VIEW_OF_FILE);
		return KFALSE;
	}
	instance->hFile = hFile;
	instance->hMap = hMap;
	instance->size = sizeof(kpacket);
	instance->sharedSecret = (ksharedsecret*)malloc(sizeof(ksharedsecret));
	kpacket pkt;
	kbool timeout = KFALSE;
	khandle hTimer = NULL;
	if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)kit_timeout, &timeout, KIT_DEFAULT_TIMEOUT, 0, WT_EXECUTEDEFAULT)) {
		kit_set_error(KIT_TIMER_ERROR);
		return KFALSE;
	}
	while (KTRUE) {
		if (!kit_read_packet(instance, &pkt)) {
			return KFALSE;
		}
		if (pkt.header.type == KIT_TYPE_BIND && pkt.header.flags == KIT_FLAG_BINDED) {
			break;
		}
		if (timeout) {
			break;
		}
	}
	if (!DeleteTimerQueueTimer(NULL, hTimer, NULL)) {
		kit_set_error(KIT_TIMER_ERROR);
		return KFALSE;
	}
	if (timeout) {
		kit_set_error(KIT_TIMEOUT_ERROR);
		return KFALSE;
	}
	if (!kit_make_packet(instance, KIT_TYPE_CONNECT, KIT_DATA_NONE, KIT_FLAG_CLIENT_HANDSHAKE, 0, 0, &pkt) || !kit_write_packet(instance, &pkt)) {
		return KFALSE;
	}
	return kit_client_handshake(instance);
}

kbool kit_client_handshake(IN pkinstance instance) {
	kuint8 client_private[ECC_PRV_KEY_SIZE];
	kuint8 client_public[ECC_PUB_KEY_SIZE];
	kuint8 server_public[ECC_PUB_KEY_SIZE];
	kuint8 shared_secret[ECC_PUB_KEY_SIZE];
	kpacket pkt;
	kbool timeout = KFALSE;
	khandle hTimer = NULL;
	if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)kit_timeout, &timeout, KIT_DEFAULT_TIMEOUT, 0, WT_EXECUTEDEFAULT)) {
		kit_set_error(KIT_TIMER_ERROR);
		return KFALSE;
	}
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_HANDSHAKE && pkt.header.flags == KIT_FLAG_SERVER_HANDSHAKE) {
			if (pkt.header.dataptr) {
				memcpy(server_public, pkt.body.bindata, pkt.body.length);
				if (!kit_fill_secure_random(client_private, ECC_PRV_KEY_SIZE)) {
					kit_set_error(KIT_KEY_GENERATION_FAILED);
					goto fail;
				}
				if (!ecdh_generate_keys(client_public, client_private)) {
					kit_set_error(KIT_KEY_GENERATION_FAILED);
					goto fail;
				}
				if (!kit_make_packet(instance, KIT_TYPE_HANDSHAKE, KIT_DATA_BINARY, KIT_FLAG_CLIENT_HANDSHAKE, ECC_PUB_KEY_SIZE, client_public, &pkt) || !kit_write_packet(instance, &pkt)) {
					kit_set_error(KIT_ERR_CREATE_PACKET);
					goto fail;
				}
				if (!ecdh_shared_secret(client_private, server_public, shared_secret)) {
					kit_set_error(KIT_SHARED_SECRET_GENERATION_FAILED);
					goto fail;
				}
				if (hkdf(SHA1, NULL, 0, shared_secret, ECC_PUB_KEY_SIZE, KSALT, KSALT_LENGTH, (kuint8 *)instance->sharedSecret, SHA1HashSize) != 0) {
					kit_set_error(KIT_KDF_FAILED);
					goto fail;
				}
				break;
			}
		}
	}
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_ACCEPT && pkt.header.flags == KIT_FLAG_ACCEPTED) {
			if (!kit_make_packet(instance, KIT_TYPE_CONNECT, KIT_DATA_NONE, KIT_FLAG_CONNECTED, 0, 0, &pkt) || !kit_write_packet(instance, &pkt)) {
				goto fail;
			}
			break;
		}
	}
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_CONNECT && pkt.header.flags == KIT_FLAG_CONNECTED) {
			if (pkt.body.datatype == KIT_DATA_BINARY) {
				instance->id = *(kuint32*)(pkt.body.bindata);
				kit_set_read(instance);
				instance->hMap = (kptr)((kuint64)instance->hMap + (instance->size * instance->id ));
				if (!DeleteTimerQueueTimer(NULL, hTimer, NULL)) {
					kit_set_error(KIT_TIMER_ERROR);
					return KNULL;
				}
				return KTRUE;
			}
		}
	}
fail:
	if (!DeleteTimerQueueTimer(NULL, hTimer, NULL)) {
		kit_set_error(KIT_TIMER_ERROR);
		return KNULL;
	}
	if (timeout) {
		kit_set_error(KIT_TIMEOUT_ERROR);
	}
	return KFALSE;
}

kuint8 kit_get_slot() {
	for (int i = 1; i < sizeof(kit_clients); i++) {
		if (kit_clients[i] == 0) {
			kit_clients[i] = 1;
			return i;
		}
	}
	return -1;
}

kvoid kit_free_slot(kuint8 slot) {
	kit_clients[slot] = 0;
}

pkclientinfo kit_listen_and_accept(IN pkinstance instance) {
	kuint8 server_private[ECC_PRV_KEY_SIZE];
	kuint8 server_public[ECC_PUB_KEY_SIZE];
	kuint8 client_public[ECC_PUB_KEY_SIZE];
	kuint8 shared_secret[ECC_PUB_KEY_SIZE];
	kpacket pkt;
	pkclientinfo info = (pkclientinfo)malloc(sizeof(kclientinfo));
	kbool timeout = KFALSE;
	khandle hTimer = NULL;
	kuint8 slot = -1;
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_CONNECT && pkt.header.flags == KIT_FLAG_CLIENT_HANDSHAKE) {
			slot = kit_get_slot();
			if (slot < 0) {
				kit_set_error(KIT_NO_MORE_SLOT);
				goto fail;
			}
			if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)kit_timeout, &timeout, KIT_DEFAULT_TIMEOUT, 0, WT_EXECUTEDEFAULT)) {
				kit_set_error(KIT_TIMER_ERROR);
				goto fail;
			}
			if (!kit_fill_secure_random(server_private, ECC_PRV_KEY_SIZE)) {
				kit_set_error(KIT_KEY_GENERATION_FAILED);
				goto fail;
			}
			if (!ecdh_generate_keys(server_public, server_private)) {
				kit_set_error(KIT_KEY_GENERATION_FAILED);
				goto fail;
			}
			if (!kit_make_packet(instance, KIT_TYPE_HANDSHAKE, KIT_DATA_BINARY, KIT_FLAG_SERVER_HANDSHAKE, ECC_PUB_KEY_SIZE, server_public, &pkt) || !kit_write_packet(instance, &pkt)) {
				goto fail;
			}
			break;
		}
	}
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_HANDSHAKE && pkt.header.flags == KIT_FLAG_CLIENT_HANDSHAKE) {
			if (pkt.header.dataptr) {
				memcpy(client_public, pkt.body.bindata, pkt.body.length);
				if (!ecdh_shared_secret(server_private, client_public, shared_secret)) {
					kit_set_error(KIT_SHARED_SECRET_GENERATION_FAILED);
					goto fail;
				}
				if (hkdf(SHA1, NULL, 0, shared_secret, ECC_PUB_KEY_SIZE, KSALT, KSALT_LENGTH, instance->sharedSecret[slot], SHA1HashSize) != 0) {
					kit_set_error(KIT_KDF_FAILED);
					goto fail;
				}
				if (!kit_make_packet(instance, KIT_TYPE_ACCEPT, KIT_DATA_NONE, KIT_FLAG_ACCEPTED, 0, 0, &pkt) || !kit_write_packet(instance, &pkt)) {
					goto fail;
				}
				break;
			}
		}
	}
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_CONNECT && pkt.header.flags == KIT_FLAG_CONNECTED) {
			if (slot > 0) {
				kptr ptr = (kptr)((kuint64)instance->hMap + (instance->size * slot));
				if (!VirtualAlloc(ptr, sizeof(kpacket), MEM_COMMIT, PAGE_READWRITE)) {
					kit_free_slot(slot);
					kit_set_error(KIT_MEMORY_RESIZE_ERROR);
					goto fail;
				}
			}
			if (!kit_make_packet(instance, KIT_TYPE_CONNECT, KIT_DATA_BINARY, KIT_FLAG_CONNECTED, sizeof(slot), &slot, &pkt) == KTRUE) {
				kit_set_error(KIT_CONNECT_FAILED);
				goto fail;
			}
			if (!kit_write_packet(instance, &pkt)) {
				goto fail;
			}
			break;
		}
	}
	while (KTRUE) {
		if (timeout) {
			goto fail;
		}
		if (!kit_read_packet(instance, &pkt)) {
			goto fail;
		}
		if (pkt.header.type == KIT_TYPE_CONNECT && pkt.header.flags == KIT_FLAG_CONNECTED && pkt.body.datatype == KIT_DATA_BINARY) {
			if (pkt.header.readed) {
				if (!kit_make_packet(instance, KIT_TYPE_BIND, KIT_DATA_NONE, KIT_FLAG_BINDED, 0, 0, &pkt) == KTRUE) {
					kit_set_error(KIT_BIND_FAILED);
					goto fail;
				}
				if (!kit_write_packet(instance, &pkt)) {
					goto fail;
				}
				break;
			}
		}
	}
	kit_set_error(KIT_OK);
	if (!DeleteTimerQueueTimer(NULL, hTimer, NULL)) {
		kit_set_error(KIT_TIMER_ERROR);
		return KNULL;
	}
	info->clientid = slot;
	info->instance.aes = instance->aes;
	info->instance.hMap = (kptr)((kuint64)instance->hMap + (instance->size * info->clientid));
	info->instance.hFile = instance->hFile;
	info->instance.size = instance->size;
	info->instance.id = instance->id;
	info->instance.sharedSecret = (ksharedsecret*)malloc(sizeof(ksharedsecret));
	memcpy(info->instance.sharedSecret, instance->sharedSecret[slot], sizeof(ksharedsecret));
	return info;
fail:
	while (KTRUE) {
		if (!kit_make_packet(instance, KIT_TYPE_BIND, KIT_DATA_NONE, KIT_FLAG_BINDED, 0, 0, &pkt) == KTRUE) {
			kit_set_error(KIT_BIND_FAILED);
		}
		if (kit_write_packet(instance, &pkt)) {
			break;
		}
	}
	free(info);
	kit_free_slot(slot);
	if (hTimer) {
		if (!DeleteTimerQueueTimer(NULL, hTimer, NULL)) {
			kit_set_error(KIT_TIMER_ERROR);
			return KNULL;
		}
		if (timeout) {
			kit_set_error(KIT_TIMEOUT_ERROR);
		}
	}
	return KNULL;
}

kbool kit_fill_secure_random(IN kptr buffer, IN ksize size) {
	CSPRNG_TYPE* csprng = csprng_create();
	if (!csprng)
		return KFALSE;
	for (int i = 0; i < size; i++)
		((kuint8*)(buffer))[i] = csprng_get_int(csprng->object) % 0xFF;
	if (!csprng_delete(csprng)) {
		kit_set_error(KIT_CRYPTO_ERROR);
		return KFALSE;
	}
	return KTRUE;
}

kvoid kit_set_error(IN kit_error errid) {
	SetLastError(errid);
}

kuint32 kit_get_error() {
	return GetLastError();
}

kcstring kit_human_error() {
	switch (kit_get_error()) {
	case KIT_OK:
		return "no error";
	case KIT_ERR_CREATE_FILE_MAPPING:
		return "unable to create file mapping";
	case KIT_ERR_MAP_VIEW_OF_FILE:
		return "unable to map view of file";
	case KIT_ERR_CREATE_PACKET:
		return "unable to create packet";
	case KIT_ERR_WRITE_MAP:
		return "unable to write mapped view of file";
	case KIT_BIND_FAILED:
		return "unable to bind";
	case KIT_INVALID_PARAMETER:
		return "error invalid parameter";
	case KIT_CONNECT_FAILED:
		return "connection failed invalid shared memory name";
	case KIT_MEMORY_READ_ERROR:
		return "unable to read memory";
	case KIT_TIMEOUT_ERROR:
		return "error timeout";
	case KIT_KEY_GENERATION_FAILED:
		return "key generation failed";
	case KIT_PACKET_MISMATCH_CRC32:
		return "error packet mismatch crc";
	case KIT_SHARED_SECRET_GENERATION_FAILED:
		return "shared secret generation failed";
	case KIT_KDF_FAILED:
		return "key derivation function failed";
	case KIT_INITIALIZATION_FAILED:
		return "error initialize failed";
	case KIT_CRYPTO_ERROR:
		return "error during crypto initialize/finalize";
	case KIT_MEMORY_RESIZE_ERROR:
		return "unable to resize mapped memory";
	case KIT_TIMER_ERROR:
		return "error during create / delete timer";
	case KIT_NO_MORE_SLOT:
		return "unable to accept more clients";
	default:
		return "unknown error";
	}
}

kbool kit_init() {
	khandle mutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, KIT_MUTEX);
	if (mutex != NULL) {
		kit_global_mutex = mutex;
		return KTRUE;
	}
	else {
		kit_global_mutex = CreateMutexA(NULL, FALSE, KIT_MUTEX);
		if (kit_global_mutex != NULL) {
			return KTRUE;
		}
		kit_set_error(KIT_INITIALIZATION_FAILED);
		return KFALSE;
	}
}

kvoid kit_encrypt_packet(IN pkinstance instance, IN pkpacket pkt) {
	kuint32 mutex_status = WaitForSingleObject(kit_global_mutex, KIT_WAIT_MUTEX);
	kuint8 randomIV[16];
	kbinary* padded;
	ksize padded_size;
	switch (mutex_status) {
	case WAIT_OBJECT_0:
		kit_fill_secure_random(randomIV, sizeof(randomIV));
		AES_init_ctx_iv(&instance->aes, (kuint8*)instance->sharedSecret, randomIV);
		padded_size = AES_pkcs7_pad_size(pkt->body.length);
		padded = AES_pkcs7_pad(pkt->body.bindata, pkt->body.length);
		memcpy(pkt->body.bindata, randomIV, sizeof(randomIV));
		memcpy(pkt->body.bindata + sizeof(randomIV), padded, padded_size);
		pkt->body.length = padded_size + sizeof(randomIV);
		AES_CBC_encrypt_buffer(&instance->aes, pkt->body.bindata + sizeof(randomIV), pkt->body.length - sizeof(randomIV));
		free(padded);
		pkt->header.crc32 = kit_crc32(pkt->body.bindata, pkt->body.length);
		ReleaseMutex(kit_global_mutex);
	case WAIT_TIMEOUT:
	default:
		return;
	}
}

kvoid kit_decrypt_packet(IN pkinstance instance, IN pkpacket pkt) {
	kuint32 mutex_status = WaitForSingleObject(kit_global_mutex, KIT_WAIT_MUTEX);
	kuint8 randomIV[16];
	kbinary* unpadded;
	ksize unpadded_size;
	switch (mutex_status) {
	case WAIT_OBJECT_0:
		memcpy(randomIV, pkt->body.bindata, sizeof(randomIV));
		AES_init_ctx_iv(&instance->aes, (kuint8*)instance->sharedSecret, randomIV);
		AES_CBC_decrypt_buffer(&instance->aes, pkt->body.bindata + sizeof(randomIV), pkt->body.length - sizeof(randomIV));
		unpadded_size = AES_pkcs7_unpad_size(pkt->body.bindata + sizeof(randomIV), pkt->body.length - sizeof(randomIV));
		unpadded = AES_pkcs7_unpad(pkt->body.bindata + sizeof(randomIV), pkt->body.length - sizeof(randomIV));
		memset(pkt->body.bindata, 0, sizeof(pkt->body.bindata));
		memcpy(pkt->body.bindata, unpadded, unpadded_size);
		pkt->body.length = unpadded_size;
		pkt->header.crc32 = kit_crc32(pkt->body.bindata, pkt->body.length);
		free(unpadded);
		ReleaseMutex(kit_global_mutex);
	case WAIT_TIMEOUT:
	default:
		return;
	}
}

kbool kit_write(IN pkinstance instance, IN kbinary* data, ksize length) {
	kpacket pkt;
	while (KTRUE) {
		if (!kit_read_packet(instance, &pkt)) {
			return KFALSE;
		}
		if (pkt.header.type != KIT_TYPE_DATA && pkt.header.flags != KIT_FLAG_DEFAULT && pkt.body.datatype != KIT_DATA_BINARY) {
			break;
		}
		else {
			if (pkt.header.readed) {
				break;
			}
		}
	}
	if (!kit_make_packet(instance, KIT_TYPE_DATA, KIT_DATA_BINARY, KIT_FLAG_DEFAULT, length, data, &pkt)) {
		return KFALSE;
	}
	kit_encrypt_packet(instance, &pkt);
	if (!kit_write_packet(instance, &pkt)) {
		return KFALSE;
	}
	return KTRUE;
}

pkpacket kit_read(IN pkinstance instance) {
	pkpacket pkt;
	while (KTRUE) {
		pkt = (pkpacket)malloc(sizeof(kpacket));
		if (pkt != NULL) {
			if (!kit_read_packet(instance, pkt)) {
				free(pkt);
				return KNULL;
			}
			else {
				if (pkt->header.type == KIT_TYPE_DATA && pkt->header.flags == KIT_FLAG_DEFAULT && pkt->body.datatype == KIT_DATA_BINARY) {
					kit_decrypt_packet(instance, pkt);
				}
				if (!pkt->header.readed && pkt->header.senderid != instance->id) {
					//kit_last_pid = pkt->header.pid;
					kit_set_read(instance);
					break;
				}
				else {
					free(pkt);
				}
			}
		}
	}
	return pkt;
}

kbool kit_disconnect(IN pkinstance instance) {
	kpacket pkt;
	if (!kit_make_packet(instance, KIT_TYPE_DISCONNECT, KIT_DATA_NONE, KIT_FLAG_DISCONNECTED, 0, KNULL, &pkt) || !kit_write_packet(instance, &pkt)) {
		return KFALSE;
	}
	return KTRUE;
}

kvoid kit_set_read(IN pkinstance instance) {
	kuint32 mutex_status = WaitForSingleObject(kit_global_mutex, KIT_WAIT_MUTEX);
	pkpacket pkt;
	switch (mutex_status) {
	case WAIT_OBJECT_0:
		pkt = (pkpacket)(instance->hMap);
		pkt->header.readed = 1;
		ReleaseMutex(kit_global_mutex);
	case WAIT_TIMEOUT:
	default:
		return;
	}
}

kit_action kit_select(IN pkinstance instance) {
	kpacket pkt;
	if (kit_read_packet(instance, &pkt)) {
		if (!pkt.header.readed && pkt.header.senderid != instance->id) {
			return KIT_CAN_READ;
		}
		else if (pkt.header.readed && pkt.header.senderid != instance->id) {
			return KIT_CAN_WRITE;
		}
	}
	return KIT_WAIT;
}
#endif
