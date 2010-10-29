#include "cobs.h"

#ifdef COBS_TEST

#define CASE(in, out) { in, out, STATIC_STRLEN(in), STATIC_STRLEN(out) }

static const struct {
  const char *in;
  const char *out;
  size_t in_len;
  size_t out_len;
} tests[] = {
  CASE("\0",   "\x01"),
  CASE("X\0",  "\x02X"),
  CASE("\0\0", "\x01\x01"),
  CASE("abc\0xy\0\0", ("\x04" "abc" "\x03xy\x01")),
};

#undef CASE

int
main(void)
{
  size_t i;

  srandom(time(NULL) ^ getpid() ^ getppid() ^ getuid());
  
//  for (i = 0; i < ARRAY_LEN(tests); i++) {
  for (;;) {
    char buf[4096];
    size_t n;
    const char *in, *out;
    size_t in_len, out_len;

    if (1) {
      static char x[4000], y[ARRAY_LEN(x)];
      size_t j, z;
      
      in = x;
      out = y;
      z = random() % (ARRAY_LEN(x) / 2);
      for (j = 0; j < z; j++) {
        x[j] = random();
      }
      x[j++] = 0x00;
      in_len = j;
      out_len = cobs_encode(y, in, in_len);
    } else {
      in = tests[i].in;
      out = tests[i].out;
      in_len = tests[i].in_len;
      out_len = tests[i].out_len;
    }

    memset(buf, 0, sizeof buf);
    n = cobs_encode(buf, in, in_len);
    RUNTIME_ASSERT(n == out_len);
    
    RUNTIME_ASSERT(NULL == memchr(buf, 0x00, n));

    n = memcmp(buf, out, n);
    RUNTIME_ASSERT(n == 0);
    
    memset(buf, 0, sizeof buf);
    n = cobs_decode(buf, out, out_len);
    RUNTIME_ASSERT(n == in_len);
    
    n = memcmp(buf, in, n);
    RUNTIME_ASSERT(n == 0);
  }

  return 0;	
}
#endif /* COBS_TEST */

/* vi: set ai et sts=2 sw=2 cindent: */
