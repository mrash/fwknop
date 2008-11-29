# $Id$
############################################################################
#
# File:    Makefile
#
# Author:  Damien Stuart
# 
# Purpose: Makefile for fwknop-c implementation
#
# Copyright (C) 2008 Damien Stuart (dstuart@dstuart.org)
#
#  License (GNU Public License):
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program; if not, write to the Free Software
#     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#     USA
#
############################################################################
#
CC      =	gcc

# Specify pcap library (typically pcap or pcap_ring).
#
PCAP_LIB = -lpcap

# Base CFLAGS
# For Full debugging (for extreme verbose output at runtime), add
# "-DDEBUG to the BASE_CFLAGS arg.  This should not be used on a
# production build.
#
BASE_CFLAGS = -Wall -fno-strict-aliasing 

# Uncomment one of these CFLAGS based on your needs
#
## Prod Build
#CFLAGS  =	-O2 $(BASE_CFLAGS)
#
## For debugging symbols if you plan to use a debugger
CFLAGS  =	-g -O0 $(BASE_CFLAGS)

LDFLAGS =	

LIBS    =	#$(PCAP_LIB) -lm -lz

PROG    =	fko_test

SRCS 	= 	fko_test.c \
			spa_random_number.c \
			spa_user.c \
			spa_timestamp.c \
			strlcat.c \
			strlcpy.c

OBJS 	=	$(SRCS:.c=.o)


###########################################################################
# Targets
#
all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

# Force a normal rebuild.
#
rebuild: clean $(PROG)

strip: $(PROG)
	strip $(PROG)

clean:
	rm -f $(PROG) $(OBJS)

realclean:
	rm -f $(PROG) $(OBJS) core *.bak *.tmp *[-~]

# Generate the dependencies for the sources in this current directory
# while ignoring warnings. Note: If you don't have makedepend in your PATH,
# you will simple get a warning and noting will happen.
#
depend:
	@`which makedepend 2>/dev/null` -Y -- $(CFLAGS) -- $(SRCS) 2> /dev/null \
		&& echo "makedepend -Y -- $(CFLAGS) -- $(SRCS) 2> /dev/null" \
		|| echo " - makedepend not found.  Aborting..."


###########################################################################
# Dependencies - (These are automatically generate with "make depend")
#
# DO NOT DELETE

fko_test.o: fwknop.h
spa_random_number.o: fwknop.h
spa_user.o: fwknop.h
spa_timestamp.o: fwknop.h
