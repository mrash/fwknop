#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include <syslog.h>

static SV *ident_svptr;

MODULE = Unix::Syslog	PACKAGE = Unix::Syslog

 # $Id: Syslog.xs 3 2004-06-25 02:18:47Z mbr $
 #
 # Copyright (C) 1999,2000,2001,2002 Marcus Harnisch <marcus.harnisch@gmx.net>
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the Artistic License. A copy of the license (see
 # file Artistic in this directory) must be included in the package.

PROTOTYPES: DISABLE

 # Log priorities
int
_LOG_PRIORITY()
ALIAS:
	LOG_EMERG   = LOG_EMERG
	LOG_ALERT   = LOG_ALERT
	LOG_CRIT    = LOG_CRIT
	LOG_ERR     = LOG_ERR
	LOG_WARNING = LOG_WARNING
	LOG_NOTICE  = LOG_NOTICE
	LOG_INFO    = LOG_INFO
	LOG_DEBUG   = LOG_DEBUG
CODE:
	RETVAL = ix;
OUTPUT:
	RETVAL

 # Log facilities
int
_LOG_FACILITY()
ALIAS:
	LOG_KERN     = LOG_KERN    
	LOG_USER     = LOG_USER    
	LOG_MAIL     = LOG_MAIL    
	LOG_DAEMON   = LOG_DAEMON  
	LOG_AUTH     = LOG_AUTH    
	LOG_SYSLOG   = LOG_SYSLOG  
	LOG_LPR      = LOG_LPR     
	LOG_NEWS     = LOG_NEWS    
	LOG_UUCP     = LOG_UUCP    
	LOG_CRON     = LOG_CRON    
	LOG_LOCAL0   = LOG_LOCAL0  
	LOG_LOCAL1   = LOG_LOCAL1  
	LOG_LOCAL2   = LOG_LOCAL2  
	LOG_LOCAL3   = LOG_LOCAL3  
	LOG_LOCAL4   = LOG_LOCAL4  
	LOG_LOCAL5   = LOG_LOCAL5  
	LOG_LOCAL6   = LOG_LOCAL6  
	LOG_LOCAL7   = LOG_LOCAL7  
CODE:
	RETVAL = ix;
OUTPUT:
	RETVAL

#if defined(LOG_AUTHPRIV)
int
LOG_AUTHPRIV()
CODE:
	RETVAL = LOG_AUTHPRIV;
OUTPUT:
	RETVAL

#endif

#if defined(LOG_FTP)
int
LOG_FTP()
CODE:
	RETVAL = LOG_FTP;
OUTPUT:
	RETVAL

#endif

 # Arguments to setlogmask
int
LOG_MASK(pri)
	int pri
CODE:
	RETVAL = LOG_MASK(pri);
OUTPUT:
	RETVAL

int
LOG_UPTO(pri)
	int pri
CODE:
	RETVAL = LOG_UPTO(pri);
OUTPUT:
	RETVAL


 # Option flags
int
_LOG_OPTIONS()
ALIAS:
	LOG_PID    = LOG_PID   
	LOG_CONS   = LOG_CONS  
	LOG_ODELAY = LOG_ODELAY
	LOG_NDELAY = LOG_NDELAY
	LOG_NOWAIT = LOG_NOWAIT
CODE:
	RETVAL = ix;
OUTPUT:
	RETVAL

#if defined(LOG_PERROR)
int
LOG_PERROR()
CODE:
	RETVAL = LOG_PERROR;
OUTPUT:
	RETVAL

#endif

#if defined(LOG_PRI)
int
LOG_PRI(pri)
	int pri
CODE:
	RETVAL = LOG_PRI(pri);
OUTPUT:
	RETVAL

#endif

#if defined(LOG_MAKEPRI)
int
LOG_MAKEPRI(fac, pri)
	int fac
	int pri
CODE:
	RETVAL = LOG_MAKEPRI(fac, pri);
OUTPUT:
	RETVAL

#endif

#if defined(LOG_FAC)
int
LOG_FAC(p)
	int p
CODE:
	RETVAL = LOG_FAC(p);
OUTPUT:
	RETVAL

#endif

#ifdef SYSLOG_NAMES
char*
priorityname(p)
	int p
INIT:
	int i;
CODE:
	for (i=0; prioritynames[i].c_val != p && prioritynames[i].c_val != -1; i++) {}
	if (prioritynames[i].c_val == -1)
	  RETVAL="";
	else
	  RETVAL=prioritynames[i].c_name;
OUTPUT:
	RETVAL

char*
facilityname(f)
	int f
INIT:
	int i;
CODE:
	for (i=0; facilitynames[i].c_val != f && facilitynames[i].c_val != -1; i++) {}
	if (facilitynames[i].c_val == -1)
	  RETVAL="";
	else
	  RETVAL=facilitynames[i].c_name;
OUTPUT:
	RETVAL

#else
char*
priorityname(p)
	int p
CODE:
	XSRETURN_UNDEF;

char*
facilityname(f)
	int f
CODE:
	XSRETURN_UNDEF;

#endif

 # Miscellaneous constants
int
LOG_NFACILITIES()
CODE:
	RETVAL = LOG_NFACILITIES;
OUTPUT:
	RETVAL

int
LOG_FACMASK()
CODE:
	RETVAL = LOG_FACMASK;
OUTPUT:
	RETVAL

 # Open connection to system logger
void
openlog(ident, option, facility)
	SV*   ident
	int   option
	int   facility
	PREINIT:
	STRLEN len;
	char*  ident_pv;
CODE:
 	ident_svptr = newSVsv(ident);
	ident_pv    = SvPV(ident_svptr, len);
	openlog(ident_pv, option, facility);

 # Internal function to generate Log message
void
_isyslog(priority, message)
	int   priority
	char *message
CODE:
	syslog(priority, "%s", message);

 # Set log mask
int
setlogmask(mask)
	int mask
	CODE:
	setlogmask(mask);

 # Close connection to system logger
void
closelog()
	CODE:
	closelog();
	if (SvREFCNT(ident_svptr)) SvREFCNT_dec(ident_svptr);
