/*
 *****************************************************************************
 *
 * File:    log_msg.c
 *
 * Author:  Damien S. Stuart
 *
 * Purpose: General logging routine that can write to syslog and/or stderr
 *          and can take varibale number of args.
 *
 * Copyright 2010-2013 Damien Stuart (dstuart@dstuart.org)
 *
 *  License (GNU Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fwknopd_common.h"
#include "utils.h"
#include "log_msg.h"

/* The default log facility (can be overridden via config file directive).
*/
static int  syslog_fac      = LOG_DAEMON;

/* This value is or'ed with the log level on all logging calls. This allows
 * for force log to stderr instead of syslog simply be setting this to the
 * appropriate value (which is done at init_logging().
*/
static int  static_log_flag = 0;

/* The name to use for ID in log messages.  This defaults to fwknopd.
*/
static char *log_name = NULL;

/* The value of the default verbosity used by the log module */
static int verbosity = LOG_DEFAULT_VERBOSITY;

/* Free resources allocated for logging.
*/
void
free_logging(void)
{
    if(log_name != NULL)
        free(log_name);
}

/* Initialize logging sets the name used for syslog.
*/
void
init_logging(fko_srv_options_t *opts) {
    char                   *my_name = NULL;
    int                     is_syslog = 0;

    /* In case this is a re-init.
    */
    free_logging();

    /* Allocate memory for the log_name and set the my_name to point to the
     * appropriate name. The name should already be set in the config struct
     * but if it is not, fallback to the default as defined by 'MY_NAME'.
    */
    if(opts->config[CONF_SYSLOG_IDENTITY] != NULL
      && opts->config[CONF_SYSLOG_IDENTITY][0] != '\0')
    {
        my_name  = opts->config[CONF_SYSLOG_IDENTITY];
        log_name = malloc(strlen(opts->config[CONF_SYSLOG_IDENTITY])+1);
        is_syslog = 1;
    }
    else
    {
        my_name  = (char*)&MY_NAME;
        log_name = malloc(strlen(MY_NAME)+1);
    }

    if(log_name == NULL)
    {
        fprintf(stderr, "Memory allocation error setting log_name!\n");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Set our name.
    */
    if (is_syslog)
        strlcpy(log_name, my_name, strlen(opts->config[CONF_SYSLOG_IDENTITY])+1);
    else
        strlcpy(log_name, my_name, strlen(MY_NAME)+1);

    /* If we are running in the foreground or performing firewall operations,
     * all logging will go to stderr.
    */
    if(opts->foreground != 0
            || opts->fw_flush != 0
            || opts->fw_list != 0
            || opts->fw_list_all != 0)
        static_log_flag = LOG_STDERR | LOG_STDERR_ONLY;

    /* Parse the log facility as specified in the config struct. If, for some
     * reason, it is not, fac will already be set to LOG_DAEMON.
    */
    if(opts->config[CONF_SYSLOG_FACILITY] != NULL
      && opts->config[CONF_SYSLOG_FACILITY][0] != '\0')
    {
        if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_DAEMON"))
            syslog_fac = LOG_DAEMON;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL0"))
            syslog_fac = LOG_LOCAL0;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL1"))
            syslog_fac = LOG_LOCAL1;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL2"))
            syslog_fac = LOG_LOCAL2;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL3"))
            syslog_fac = LOG_LOCAL3;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL4"))
            syslog_fac = LOG_LOCAL4;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL5"))
            syslog_fac = LOG_LOCAL5;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL6"))
            syslog_fac = LOG_LOCAL6;
        else if(!strcasecmp(opts->config[CONF_SYSLOG_FACILITY], "LOG_LOCAL7"))
            syslog_fac = LOG_LOCAL7;
    }

    verbosity = LOG_DEFAULT_VERBOSITY + opts->verbose;
}

/* Set the log facility value.
*/
void
set_log_facility(int fac)
{
    syslog_fac = fac;
}

/* Syslog message function.  It uses default set at intialization, and also
 * takes variable args to accomodate printf-like formatting and expansion.
*/
void
log_msg(int level, char* msg, ...)
{
    va_list ap, apse;

    if ((level & LOG_VERBOSITY_MASK) > verbosity)
        return;

    va_start(ap, msg);

    level |= static_log_flag;

    /* Print msg to stderr if the level was or'ed with LOG_STDERR
    */
    if(LOG_STDERR & level)
    {
        /* Need to make a copy of our va_list so we don't screw
         * up the message going to syslog after we print it to stderr.
        */
        va_copy(apse, ap);

        vfprintf(stderr, msg, apse);
        fprintf(stderr, "\n");
        fflush(stderr);

        va_end(apse);
    }

    /* If the message has not to be printed to the syslog, we return */
    if (LOG_WITHOUT_SYSLOG & level)
    {
        va_end(ap);
        return;
    }

    /* Remove the log to stderr flag from the log level value.
    */
    level &= LOG_VERBOSITY_MASK;

    /* Send the message to syslog.
    */
    openlog(log_name, LOG_PID, syslog_fac);

    vsyslog(level, msg, ap);

    va_end(ap);
}

/**
 * Set the verbosity level for the current context of the log module.
 *
 * The verbosity levels used byt the module are defined by the sylsog module.
 *
 * @param level verbosity level to set (LOG_INFO, LOG_NOTICE ...)
 */
void
log_set_verbosity(int level)
{
    verbosity = level;
}

/***EOF***/
