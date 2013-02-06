CC      = gcc
NOCRYPT =

# Debugging flags possible:  DEBUG_MEM DEBUG_MEM_CORRUPT DEBUG_MEM_DUP_FREE
# DEBUG_MEM is most basic, just checks magic numbers when freeing
# DEBUG_MEM_CORRUPT checks every free block to see if magic numbers ok, every
#                   call to alloc_mem
#		    Also makes calls to void check_free_mem(void) check for
#		    corrupted free memory blocks.
# DEBUG_MEM_DUP_FREE checks to see if freed blocks are overlapping every call
# 		     to mem_alloc.
#
#DEBUG =  -DDEBUG_MEM -DDEBUG_MEM_CORRUPT -DDEBUG_MEM_DUP_FREE

#IMC2 - Comment out to disable IMC2 support
#IMC = 1
#C_FLAGS = -O -g3 -Wall -DACK_43 $(PROF) $(NOCRYPT) 
#C_FLAGS = -g3 -Wall ($PROF) $(NOCRYPT) -DOLD_RAND -Dunix
#-DDEBUG_MEM -DDEBUG_MEM_CORRUPT
# MCCP
# End MCCP
#L_FLAGS = $(PROF)

PROF    =-O0 -g3#      -pg -DUSE_MCHECK
LIBS    = -lcrypt -lz #-lgd
L_FLAGS =$(PROF) -ggdb3 -o0  -D_GNU_SOURCE
E_FLAGS =#            -Lefence/ -lefence -DMALLOC_DEBUG
O_FLAGS =$(PROF)
C_FLAGS =-O0 $(WARNINGS) -DLARGEFILE_SOURCE=1 $(O_FLAGS) -DACK_43 $(NOCRYPT) $(DEBUG)
.SUFFIXES:
.SUFFIXES: .c .o

# -L/usr/local/lib 

O_FILES = act_comm.o act_info.o act_move.o act_obj.o act_wiz.o comm.o const.o \
          db.o fight.o handler.o interp.o engineer.o \
          save.o update.o board.o areasave.o buildings.o \
          buildtab.o build.o write.o buildare.o hash.o areachk.o \
          macros.o lists.o social-edit.o hack.o space.o \
          logs.o pdelete.o wizutil.o brands.o terrain.o web.o \
          ssm.o scheck.o sysdata.o strfuns.o mapper.o email.o \
          act_misc.o mccp.o mxp.o games.o act_skills.o act_alliance.o


#   C_FILES := imc.c md5.c $(C_FILES)
#   O_FILES := imc.o md5.o $(O_FILES)
#   C_FLAGS := $(C_FLAGS) -DIMCACK

ack: $(O_FILES)
	rm -f ack
	$(CC) $(L_FLAGS) -o ack $(O_FILES) $(LIBS)
	rm -f /ack

.c.o: ack.h
	$(CC) -c $(C_FLAGS) $<

scan: scan.o
	rm -f scan
	$(CC) $(L_FLAGS) -o scan scan.o -lcrypt

clean:
	rm -f $(O_FILES) ack ../area/core
#	make

WARNINGS= -Wstrict-prototypes \
	-Wpointer-arith \
	-Wno-char-subscripts \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wshadow -Wformat=2 -Waggregate-return \
	-Winline \
	-Waddress \
	-Warray-bounds \
	-Wchar-subscripts \
	-Wenum-compare \
	-Wimplicit-int \
	-Wimplicit-function-declaration \
	-Wcomment \
	-Wmain \
	-Wmissing-braces \
	-Wnonnull \
	-Wparentheses \
	-Wpointer-sign \
	-Wreturn-type \
	-Wsequence-point \
	-Wsign-compare \
	-Wstrict-aliasing \
	-Wstrict-overflow=1 \
	-Wswitch \
	-Wtrigraphs \
	-Wuninitialized \
	-Wunknown-pragmas \
	-Wunused-function \
	-Wunused-label \
	-Wunused-value \
	-Wvolatile-register-var
# Suppressed warnings (not listed: ones included in Wall):
#-Wunused-variable
#-Wmissing-prototypes
#-Wmissing-declarations
# Notes:
# reorder enabled by default
# maybe-uninitialized was not available
# enum-compare (in C/ObjC; this is on by default in C++) 
# array-bounds (only with -O2)  
# implicit-function-declaration (C and Objective-C only) 
# main (only for C/ObjC and unless -ffreestanding)  
# missing-braces (only for C/ObjC)
# sign-compare (only in C++)
