#include <stdio.h>
#include <openssl/bn.h>


int main (){
  //A BN_CTX is a structure that holds BIGNUM temporary variables used by library functions
  BN_CTX *ctx = BN_CTX_new();

  unsigned char *n_str = "abcdef0123456789";
  //you need to new a bignum dynamically
  BIGNUM *n = BN_new();
  //convern a hex string to n. The library automatically extend the needed memory for us if necessary
  //note the & operator. The prototype of BN_hex2bn can be found in the official OpenSSL document
  BN_hex2bn(&n, n_str);

  //verify the construction of big number
  printf("n: ");
  BN_print_fp(stdout, n);
  printf("\n");

  //now let's do more arithmetic operations
  //r to store the result t to store a temperary variable
  BIGNUM *r = BN_new();
  BIGNUM *r2 = BN_new();
  BIGNUM *t = BN_new();
  //initialize t
  BN_hex2bn(&t, "ABC");

  //r = n + t
  BN_add(r, n, t);
  printf("n+t: ");
  BN_print_fp(stdout, r);
  printf("\n");

  //r = r - t
  BN_sub(r, r, t);
  printf("n+t-t: ");
  BN_print_fp(stdout, r);
  printf("\n");
  
  //r = n * t
  BN_mul(r, n, t, ctx);
  printf("n*t: ");
  BN_print_fp(stdout, r);
  printf("\n\n");

  // Declaring the things
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  //making 1 a BIGNUM because idk how to subtract otherwise
  BIGNUM *o = BN_new();
  BN_hex2bn(&o, "1");
  BN_hex2bn(&p, "d3aefa92ecf2bf9c46097c1b73f379630341f206cc1de1dbc39503741c3e717093340d069dd6564a3c05f5d549374f5a79d060e75ad29c8af02db91a34b371cc0a6b12936cd170def4322bbca99d105375435720dc31724a15ecb64bd70d4e165d04836fad827f00bd7b9eee16b479f9ab68be08a50be7216b0059b070a048fd");
  BN_hex2bn(&q, "c0d511b6738e5d1cd64a01dffe5bdd398a2f9fc1fd6cb9d8e655c61aa20726dff14dfd95bbf963067b93aec38ed927d1a0e10312e91e7d1d2619703dc54ee555644d36bcc506f0bdfb53a800bb8ae995a6c5d09a6e92b50b2e91f2fbcb385aaffa4357020abefe325be4494ee12a1ef17343f70dfbae15655558bb24dbcbfee3");
  BN_hex2bn(&e, "10001");
  BIGNUM *phi = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *m = BN_new();
  BN_hex2bn(&m, "54686973206973206120736563726574206d65737361676521");
  BIGNUM *c = BN_new();
  BIGNUM *m2 = BN_new();

  // Doin' the math for part 2:
  BN_mul(n, p, q, ctx);
  BN_sub(r, p, o);
  BN_sub(r2, q, o);
  BN_mul(phi, r, r2, ctx);
  BN_mod_inverse(d, e, phi, ctx);

  //Doin' the math for part 3:
  BN_mod_exp(c, m, e, n, ctx);

  //Doin' the math for part 4:
  BN_mod_exp(m2, c, d, n, ctx);


  //test shiz
  printf("PART 2:\n\n");
  printf("p: ");
  BN_print_fp(stdout, p);
  printf("\n");
  printf("q: ");
  BN_print_fp(stdout, q);
  printf("\n");
  printf("phi(n): ");
  BN_print_fp(stdout, phi);
  printf("\n");
  printf("d: ");
  BN_print_fp(stdout, d);
  printf("\n");
  printf("Length of n in bits: %d", BN_num_bits(n));
  printf("\n\n");
  printf("PART 3:\n\n");
  printf("pre-encrypted Message: ");
  BN_print_fp(stdout, m);
  printf("\n");
  printf("C: ");
  BN_print_fp(stdout, c);
  printf("\n\n");
  printf("PART 4:\n\n");
  printf("pre-encrypted Message: ");
  BN_print_fp(stdout, m);
  printf("\n");
  printf("post-decrypted Message: ");
  BN_print_fp(stdout, m2);
  printf("\n");
  
  
  //don't forget to free the memory
  BN_free(n);
  BN_free(r);
  BN_free(r2);
  BN_free(t);
  BN_free(p);
  BN_free(q);
  BN_free(e);
  BN_free(d);
  BN_free(o);
  BN_free(phi);
  BN_free(m);
  BN_free(c);
  BN_free(m2);
  BN_CTX_free(ctx);
  return 0;
}
