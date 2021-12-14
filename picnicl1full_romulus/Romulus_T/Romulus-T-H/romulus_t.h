int romulus_t_encrypt (
      	unsigned char* c, unsigned long long* clen,
      	const unsigned char* m, unsigned long long mlen,
      	const unsigned char* ad, unsigned long long adlen,
      	const unsigned char* nsec,
      	const unsigned char* npub,
      	const unsigned char* k
		      );

int romulus_t_decrypt(
        unsigned char *m,unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c,unsigned long long clen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
		      );

int no_AEAD_romulus_t_encrypt (
        unsigned char* c, unsigned long long* clen,
        const unsigned char* m, unsigned long long mlen,
        const unsigned char* ad, unsigned long long adlen,
        const unsigned char* nsec,
        const unsigned char* npub,
        const unsigned char* k
          );

int no_AEAD_romulus_t_decrypt(
        unsigned char *m,unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c,unsigned long long clen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
          );


