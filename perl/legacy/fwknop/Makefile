#
##########################################################################
#
#  Author: Michael Rash (mbr@cipherdyne.org)
#
#  Version: 0.1
#
#  Copyright (C) 2004-2006 Michael Rash (mbr@cipherdyne.org)
#
#  License (GNU General Public License):
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
##########################################################################
#
#  $Id: Makefile 1201 2008-08-13 02:03:02Z mbr $
#

OPTS = -Wall -O

### default
all : knopmd.c knopwatchd.c fwknop_funcs.c strlcpy.c strlcat.c fwknop.h
	/usr/bin/gcc $(OPTS) knopmd.c fwknop_funcs.c strlcpy.c strlcat.c -o knopmd
	/usr/bin/gcc $(OPTS) knopwatchd.c fwknop_funcs.c strlcpy.c strlcat.c -o knopwatchd

### debug mode
debug : knopmd.c knopwatchd.c fwknop_funcs.c strlcpy.c strlcat.c fwknop.h
	/usr/bin/gcc -Wall -g -DDEBUG knopmd.c fwknop_funcs.c strlcpy.c strlcat.c -o knopmd
	/usr/bin/gcc -Wall -g -DDEBUG knopwatchd.c fwknop_funcs.c strlcpy.c strlcat.c -o knopwatchd

#install : knopmd
#	if [ -x knopmd ]; then \
#		/bin/cp knopmd /usr/sbin/knopmd

clean :
	if [ -f a.out ]; then rm a.out; fi
	if [ -f core ]; then rm core; fi
	if [ -f knopmd ]; then rm knopmd; fi
	if [ -f knopwatchd ]; then rm knopwatchd; fi
