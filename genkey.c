#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>

// bitcoin
const int pubKeyVersion = 0;
const int privKeyVersion = 128;

// litecoin
//const int pubKeyVersion = 48;
//const int privKeyVersion = 176;

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
    printf ( "error: possible leading zero sqashing\n" );
    exit ( 3 );
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
  while ( *q == 0 ) {  // add leading zero back in
    *p = Base58[0];
    p--;
    q++;
  }
  p++;
  return p;  // p points into the scratch buffer passed in
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
  if ( BN_num_bytes(x) != 32 ) {
    printf ( "error bad public key x (leading zeros?)\n" );
    exit ( 2 );
  }
  if ( BN_num_bytes(y) != 32 ) {
    printf ( "error bad public key y (leading zeros?)\n" );
    exit ( 2 );
  }
  if ( !BN_bn2bin ( x, scratch ) ) {
    printf ( "error: converting x\n" );
    exit ( 2 );
  }
  if ( !BN_bn2bin ( y, scratch + 32 ) ) {
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

int main() {
  group = EC_GROUP_new_by_curve_name ( NID_secp256k1 );
  if ( group == NULL ) {
    printf ( "error %d\n", __LINE__ );
    exit(1);
  }
  
  B58 = BN_new();
  BN_dec2bn ( &B58, "58" );

  uint8_t privdata[32];
  int fd = open ( "/dev/urandom", O_RDONLY );
  read ( fd, privdata, sizeof privdata );
  close ( fd );

  // allocations passed to functions for efficency
  //   was using this code to generate vanity addresses.
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();

  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* num = BN_new();
  BIGNUM* dv = BN_new();
  BIGNUM* rem = BN_new();
  uint8_t scratch[SCRATCH_SIZE];

  BIGNUM* privkey = BN_new();

  BN_bin2bn ( privdata, sizeof privdata, privkey );

  // print out the private key in hex, the private key in wallet import format and the public address
  BN_print_fp ( stdout, privkey ); printf ( "\n" );
  char* k = WIFPrivateKey ( privkey, ctx, num, dv, rem, scratch );
  printf ( "%s\n", k );
  char* pub = PublicAddress ( calcECPubkey ( group, x, y, privkey, scratch ), ctx, num, dv, rem );
  printf ( "%s\n", pub );
}
