#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* try to be compatible with older perls */
/* SvPV_nolen() macro first defined in 5.005_55 */
/* this is slow, not threadsafe, but works */
#include "patchlevel.h"
#if (PATCHLEVEL == 4) || ((PATCHLEVEL == 5) && (SUBVERSION < 55))
static STRLEN nolen_na;
# define SvPV_nolen(sv) SvPV ((sv), nolen_na)
#endif

#include "rijndael.h"

typedef struct cryptstate {
  RIJNDAEL_context ctx;
  UINT8 iv[RIJNDAEL_BLOCKSIZE];
  int mode;
} *Crypt__Rijndael;

MODULE = Crypt::Rijndael		PACKAGE = Crypt::Rijndael

PROTOTYPES: ENABLE

  # newCONSTSUB is here as of 5.004_70

BOOT:
{
#if (PATCHLEVEL > 4) || ((PATCHLEVEL == 4) && (SUBVERSION >= 70))
  HV *stash = gv_stashpv("Crypt::Rijndael", 0);

  newCONSTSUB (stash, "keysize",    newSViv (32)        );
  newCONSTSUB (stash, "blocksize",  newSViv (16)        );
  newCONSTSUB (stash, "MODE_ECB",   newSViv (MODE_ECB)  );
  newCONSTSUB (stash, "MODE_CBC",   newSViv (MODE_CBC)  );
  newCONSTSUB (stash, "MODE_CFB",   newSViv (MODE_CFB)  );
  newCONSTSUB (stash, "MODE_PCBC",  newSViv (MODE_PCBC) );
  newCONSTSUB (stash, "MODE_OFB",   newSViv (MODE_OFB)  );
  newCONSTSUB (stash, "MODE_CTR",   newSViv (MODE_CTR)  );
#endif
}

#if (PATCHLEVEL < 4) || ((PATCHLEVEL == 4) && (SUBVERSION < 70))

int
keysize(...)
  CODE:
     RETVAL=32;
  OUTPUT:
     RETVAL

int
blocksize(...)
  CODE:
     RETVAL=16;
  OUTPUT:
     RETVAL

int
MODE_ECB(...)
  CODE:
     RETVAL=MODE_ECB;
  OUTPUT:
     RETVAL

int
MODE_CBC(...)
  CODE:
     RETVAL=MODE_CBC;
  OUTPUT:
     RETVAL

int
MODE_CFB(...)
  CODE:
     RETVAL=MODE_CFB;
  OUTPUT:
     RETVAL

int
MODE_PCBC(...)
  CODE:
     RETVAL=MODE_PCBC;
  OUTPUT:
     RETVAL

int
MODE_OFB(...)
  CODE:
     RETVAL=MODE_OFB;
  OUTPUT:
     RETVAL

int
MODE_CTR(...)
  CODE:
     RETVAL=MODE_CTR;
  OUTPUT:
     RETVAL

#endif


Crypt::Rijndael
new(class, key, mode=MODE_ECB)
        SV *	class
        SV *	key
        int	mode
        CODE:
        {
          STRLEN keysize;
          
          if (!SvPOK (key))
            croak("key must be a string scalar");

          keysize = SvCUR(key);

          if (keysize != 16 && keysize != 24 && keysize != 32)
            croak ("wrong key length: key must be 128, 192 or 256 bits long");
          if (mode != MODE_ECB && mode != MODE_CBC && mode != MODE_CFB && mode != MODE_OFB && mode != MODE_CTR)
            croak ("illegal mode, see documentation for valid modes");

          Newz(0, RETVAL, 1, struct cryptstate);
	  RETVAL->ctx.mode = RETVAL->mode = mode;
	  /* set the IV to zero on initialization */
	  memset(RETVAL->iv, 0, RIJNDAEL_BLOCKSIZE);
          rijndael_setup(&RETVAL->ctx, keysize, (UINT8 *) SvPV_nolen(key));

	}
	OUTPUT:
        RETVAL

SV *
set_iv(self, data)
	Crypt::Rijndael self
	SV *	data

	CODE:
	{
	  SV *res;
	  STRLEN size;
	  void *rawbytes = SvPV(data,size);

	  if( size !=  RIJNDAEL_BLOCKSIZE )
	  	croak( "set_iv: initial value must be the blocksize (%d bytes), but was %d bytes", RIJNDAEL_BLOCKSIZE, size );
	  memcpy(self->iv, rawbytes, RIJNDAEL_BLOCKSIZE);
	}

SV *
encrypt(self, data)
        Crypt::Rijndael self
        SV *	data
        ALIAS:
        	decrypt = 1
        CODE:
        {
          SV *res;
          STRLEN size;
          void *rawbytes = SvPV(data,size);

          if (size) {
	    if (size % RIJNDAEL_BLOCKSIZE)
	      croak ("encrypt: datasize not multiple of blocksize (%d bytes)", RIJNDAEL_BLOCKSIZE);

	    RETVAL = NEWSV (0, size);
	    SvPOK_only (RETVAL);
	    SvCUR_set (RETVAL, size);
	    (ix ? block_decrypt : block_encrypt)
	      (&self->ctx, rawbytes, size, (UINT8 *) SvPV_nolen(RETVAL), self->iv);
          } else
            RETVAL = newSVpv ("", 0);
        }
	OUTPUT:
        RETVAL


void
DESTROY(self)
        Crypt::Rijndael self
        CODE:
        Safefree(self);
