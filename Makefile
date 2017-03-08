#
# This is Makefile for the secure ECDSA program.  
#
# 'make depend' uses makedepend to automatically generate dependencies 
#               (dependencies are added to end of Makefile)
# 'make' or 'make ecdsa' will build executable file 'mycc'
# 'make clean'  removes all .o and executable files
#


# define some Makefile variables for the compiler and compiler flags
# to use Makefile variables later in the Makefile: $()
#

# define the C source files
SRCS = 	field_ops.c ec_cpy.c ec_dup.c ec_free.c ec_inits.c ec_lib.c ec_ops.c ec_prn.c \
 eck_cpy.c eck_dup.c eck_free.c eck_inits.c eck_lib.c eck_prn.c \
 ecp_cmp.c ecp_compress.c ecp_convers.c ecp_cpy.c ecp_dup.c ecp_free.c ecp_inits.c \
 ecp_inverse.c ecp_is_inverse.c ecp_is_on_curve.c ecp_is_point_at_infinity.c ecp_lib.c ecp_prn.c \
 ecs_cmp.c ecs_cpy.c ecs_dup.c ecs_free.c ecs_genkey.c ecs_inits.c ecs_lib.c ecs_prn.c ecs_sgn.c ecs_vrf.c \
 hash_functions.c utils.c get_dgst.c data_parser.c

OBJS = $(SRCS:.c = .o)
HF_OBJS = hash_functions.o hashtest.o
FF_OBJS = $(OBJS) fftest.o
EC_OBJS = $(OBJS) ectest.o
ECS_OBJS = $(OBJS) ecstest.o
PROG_OBJS = $(OBJS) ecdsa.o
 
DEPS = ecdsa.h ec.h field_ops.h hashfunctions.h ec_point.h utils.h cpucycles.h

# define the C compiler to use
CC			 = gcc

# define any libraries to link into executable
LIBS 		 = -lgmp

#  define any compile-time flags. 
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
#
CFLAGS  = -g -Wall 

#  define the executable files 
PROG 		= ecdsa
HFTEST 		= hashtest
FFTEST		= fftest
ECTEST		= ectest
ECSTEST		= ecstest 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
all: $(SRCS) $(PROG) $(HFTEST) $(FFTEST) $(ECTEST) $(ECSTEST)

$(PROG): $(PROG_OBJS)
	$(CC) -o $(PROG) $(PROG_OBJS) $(CFLAGS) $(LIBS)
 
$(HFTEST): $(HF_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) 

$(FFTEST): $(FF_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	
$(ECTEST): $(EC_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
 
$(ECSTEST): $(ECS_OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
 
#
# The following part of the makefile is generic; it can be used to 
# build any executable just by changing the definitions above and by
# deleting dependencies appended to the file from 'make depend'
#
.PHONY: depend clean

depend: $(SRCS)
	makedepend $^
        
clean:
	rm -f *.o *~ $(PROG) $(HFTEST) $(ECTEST)
