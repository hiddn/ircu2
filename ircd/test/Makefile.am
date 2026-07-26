AM_CPPFLAGS = -I$(top_srcdir)/include -I../..
AM_CFLAGS = -g -Wall

check_PROGRAMS = cidr_lookups_t ircd_chattr_t ircd_in_addr_t ircd_match_t ircd_string_t

TESTS = $(check_PROGRAMS)

cidr_lookups_t_CPPFLAGS = $(AM_CPPFLAGS) -DIRCU2_BUILD
cidr_lookups_t_SOURCES = cidr_lookups_t.c test_stub.c
cidr_lookups_t_LDADD = ../cidr_lookups.o ../ircd_string.o

ircd_chattr_t_SOURCES = ircd_chattr_t.c test_stub.c
ircd_chattr_t_LDADD = ../ircd_string.o

ircd_in_addr_t_SOURCES = ircd_in_addr_t.c test_stub.c
ircd_in_addr_t_LDADD = ../ircd_alloc.o ../ircd_string.o ../match.o ../numnicks.o

ircd_match_t_SOURCES = ircd_match_t.c test_stub.c
ircd_match_t_LDADD = ../ircd_string.o ../match.o

ircd_string_t_SOURCES = ircd_string_t.c test_stub.c
ircd_string_t_LDADD = ../ircd_string.o
