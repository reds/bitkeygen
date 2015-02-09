#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>

#include <pthread.h>

// bitcoin
int pubKeyVersion = 0;
int privKeyVersion = 128;

BIGNUM* B58;
EC_GROUP* group;
#define SCRATCH_SIZE 1024 * 100

static const char* Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char* base58check ( const uint8_t* data, int len,  // what I need here
		    // allocated earlier for efficency
		    BN_CTX* ctx,
		    BIGNUM* num, BIGNUM* dv, BIGNUM* rem, uint8_t* out ) 
{   
  // append 4 byte check
  memcpy ( out, data, len );
  uint8_t sout[32];
  SHA256 ( data, len, sout );
  SHA256 ( sout, 32, sout );
  memcpy ( out + len, sout, 4 );

  // convert to base58
  if ( BN_bin2bn ( out, len + 4, num ) == NULL ) {
    ERR_print_errors ( stderr );
    exit(5);
  }

  if ( len + 3 > BN_num_bytes ( num ) ) {  // allow for 1 leading zero squash (public address)
    //    printf ( "error: possible leading zero sqashing\n" );
    //    exit ( 3 );
  }

  char* p = out + SCRATCH_SIZE - 1; 
  *p = '\0';
  p--;
  while ( !BN_is_zero(num) ) {
    if ( BN_div ( dv, rem, num, B58, ctx ) == 0 ) {
      unsigned long en = ERR_get_error ();
      printf ( "%s\n", ERR_error_string ( en, NULL ) );
      exit(1);
    }
    BN_copy ( num, dv );
    uint8_t n;
    BN_bn2bin ( rem, &n );
    *p = Base58[n];
    p--;
    n = 0;
  }
  uint8_t* q = data;
  while ( *q == 0 ) {  // add leading zeros back in
    *p = Base58[0];
    p--;
    q++;
  }
  p++;
  return p;  // p points int a scratch buffer allocated by thread
}

uint8_t* PublicAddress ( uint8_t* scratch, BN_CTX* ctx, BIGNUM* num, BIGNUM* dv, BIGNUM* rem ) {
  uint8_t a[65];
  a[0] = 4;
  memcpy ( a + 1, scratch, 64 );
  uint8_t sout[32];
  SHA256 ( a, 65, sout );
  uint8_t rout[21];
  rout[0] = pubKeyVersion;
  RIPEMD160 ( sout, 32, rout + 1 );
  return base58check ( rout, sizeof rout, ctx, num, dv, rem, scratch );
}

uint8_t* calcECPubkey ( const EC_GROUP* group, BIGNUM* x, BIGNUM* y, const BIGNUM* privkey, uint8_t* scratch ) {
  EC_POINT* pubpoint = EC_POINT_new(group);
  if ( EC_POINT_mul(group, pubpoint, privkey, NULL, NULL, NULL) == 0 ) {
    printf ( "error %d\n", __LINE__ );
    exit(1);
  }
  int r = EC_POINT_get_affine_coordinates_GFp(group, pubpoint, x, y, NULL);
  if ( r == 0 ) {
    printf ( "error %d\n", __LINE__ );
    exit(1);
  }
  memset ( scratch, 0, 64 );
  if ( !BN_bn2bin ( x, scratch + BN_num_bytes(x) - 32 ) ) {
    printf ( "error: converting x\n" );
    exit ( 2 );
  }
  if ( !BN_bn2bin ( y, scratch + 32 + BN_num_bytes(y) - 32 ) ) {
    printf ( "error: converting x\n" );
    exit ( 2 );
  }
  return scratch;
}

uint8_t* WIFPrivateKey ( BIGNUM* privkey, BN_CTX* ctx, BIGNUM* num, BIGNUM* dv, BIGNUM* rem, uint8_t* scratch ) {
  uint8_t pk[33];
  BN_bn2bin ( privkey, pk + 1 );
  pk[0] = privKeyVersion;
  return base58check ( pk, sizeof pk, ctx, num, dv, rem, scratch );
}

struct threadParams {
  char* str;
  int anywhere;
  int offset;
  uint8_t randStart[32];
  uint64_t cnt;
  int go;
};

void* run (void* param) {
  struct threadParams* tp = (struct threadParams*)param;
  // allocations per thread, passed to subroutines for efficency
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();

  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* num = BN_new();
  BIGNUM* dv = BN_new();
  BIGNUM* rem = BN_new();
  uint8_t scratch[SCRATCH_SIZE];

  BIGNUM* privkey = BN_new();
  uint8_t* privdata = tp->randStart;
  uint64_t* p = privdata + tp->offset;
  if ( *p == 0 ) {
    *p = 1;
  }
  char* str = tp->str;
  tp->cnt = 0;
  if ( str == NULL ) {  // non vanity
    BN_bin2bn ( privdata, 32, privkey );
    char* pub = PublicAddress ( calcECPubkey ( group, x, y, privkey, scratch ), ctx, num, dv, rem );
    char* addr = strdup ( pub );  // pub is in scratch, which is about to be reused
    char* k = WIFPrivateKey ( privkey, ctx, num, dv, rem, scratch );
    BN_print_fp ( stdout, privkey ); printf ( "\n" );
    printf ( "%s\n%s\n", k, addr );
    return 0;
  }
  while ( tp->go &&  *p ) {
    BN_bin2bn ( privdata, 32, privkey );
    char* pub = PublicAddress ( calcECPubkey ( group, x, y, privkey, scratch ), ctx, num, dv, rem );
    if ( strstr ( pub + 1, str ) != NULL ) {
      if ( tp->anywhere == 0 ) {  // must be at the begining
	if ( strstr ( pub + 1, str ) != pub + 1 ) {
	  continue;
	}
      }
      char* addr = strdup ( pub );  // pub is in scratch, which is about to be reused
      char* k = WIFPrivateKey ( privkey, ctx, num, dv, rem, scratch );
      BN_print_fp ( stdout, privkey ); printf ( "\n" );
      printf ( "%s\n%s\n", k, addr );
      return 0;
    }
    (*p)++;
    tp->cnt++;
  }
}

void usage () {
  printf ( "-s string: generate a public address with the given string\n"
	   "-t number: number of threads to use\n"
	   "-a: allow the string to be anywhere in the public address, not just at the begining\n"
	   "-c: the string should be case sensitive\n"
	   "-l: generate a litecoin key/address pair\n"
	   "-v verbose\n"
	   "examples:\n"
	   "\tgenerate a private key and its public address\n\t\t ./genkey\n"
	   "\tgenerate a private key where the public address contains the string \'BiT\'\n"
	   "\t\t./genkey -s BiT -c -t 8\n"
	   );
  exit(0);
}

void checkString58 ( char* in ) {
  char* p = in;
  char* invalid = strdup ( in );
  char* q = invalid;
  int invalidFound = 0;
  while ( *p ) {
    if ( strchr ( Base58, *p ) != NULL ) {
      *q = '.';
    } else {
      invalidFound++;
    }
    p++; q++;
  }
  if ( invalidFound ) {
    printf ( "Error: %d invalid base85 characters found: %s\n", invalidFound, invalid );
    exit ( 1 );
  }
}

int main( int argc, char* argv[] ) {
  int numthreads = 1;
  char* str = NULL;
  int anywhere = 0;
  int casesensitive = 0;
  int verbose = 0;

  int ch;
  while ((ch = getopt(argc, argv, "t:acs:vlh")) != -1) {
    switch (ch) {
    case 't':
      numthreads = atoi ( optarg );
      break;
    case 'a':
      anywhere = 1;
      break;
    case 'c':
      casesensitive = 1;
      break;
    case 's':
      str = strdup ( optarg );
      checkString58 ( str );
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
      usage();
      break;
    case 'l':
      pubKeyVersion = 48;
      privKeyVersion = 176;
      break;
    }
  }
  if ( numthreads == 0 ) {
    numthreads = 1;
  }
  uint8_t rand[32];
  int fd = open ( "/dev/urandom", O_RDONLY );
  read ( fd, rand, sizeof rand );
  close ( fd );

  // some global stuff
  group = EC_GROUP_new_by_curve_name ( NID_secp256k1 );
  if ( group == NULL ) {
    printf ( "error %d\n", __LINE__ );
    exit(1);
  }
  B58 = BN_new();
  BN_dec2bn ( &B58, "58" );
  
  pthread_t t;
  int i;
  struct threadParams** tplist = malloc ( sizeof ( struct threadParams* ) * numthreads );
  for ( i = 0; i < numthreads; i++ ) {
    tplist[i] = malloc ( sizeof ( struct threadParams ) );
    tplist[i]->str = str;
    tplist[i]->anywhere = anywhere;
    tplist[i]->offset = 1 + i;
    tplist[i]->cnt = 0;
    tplist[i]->go = 1;
    memcpy ( tplist[i]->randStart, rand, sizeof rand );
    pthread_create ( &t, NULL, run, (void*) tplist[i] );
  }
  // kinda getto here, if the last thread finishes just bail
  int status;
  pthread_join ( t, &status );
  uint64_t cnt = 0;
  for ( i = 0; i < numthreads; i++ ) {
    cnt += tplist[i]->cnt;
    tplist[i]->go = 0;
  }
  if ( verbose ) {
    printf ( "tried %u\n", cnt );
  }
  return 0;
}
