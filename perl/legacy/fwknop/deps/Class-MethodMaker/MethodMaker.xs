#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

MODULE = Class::MethodMaker PACKAGE = Class::MethodMaker

void
set_sub_name(SV *sub, char *pname, char *subname, char *stashname)
  CODE:
    CvGV((GV*)SvRV(sub)) = gv_fetchpv(stashname, TRUE, SVt_PV);
    GvSTASH(CvGV((GV*)SvRV(sub))) = gv_stashpv(pname, 1);
#ifdef gv_name_set
    gv_name_set(CvGV((GV*)SvRV(sub)), subname, strlen(subname), GV_NOTQUAL);
#else
    GvNAME(CvGV((GV*)SvRV(sub))) = savepv(subname);
    GvNAMELEN(CvGV((GV*)SvRV(sub))) = strlen(subname);
#endif
