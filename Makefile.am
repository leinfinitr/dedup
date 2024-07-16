bin_PROGRAMS = dedup hfstat hashconcat fstree-mutate fstree-chk hash2fstree

dedup_SOURCES = dedup.c hashfilelib.c hashfilelib.h liblog.c liblog.h murmurhash3.c murmurhash3.h

hfstat_SOURCES = hfstat.c hashfilelib.c hashfilelib.h liblog.c liblog.h

hashconcat_SOURCES = hashconcat.c hashfilelib.c hashfilelib.h liblog.c liblog.h

fstree_mutate_SOURCES = fstree-mutate.c fstree.c fstree.h rbtree.c rbtree.h \
			       fstree-mutate.h fsdistro.h fsdistro.c chunk-distro.c

fstree_chk_SOURCES = fstree-chk.c fstree.c fstree.h

#
# Uses MD5 directly - fixit.
#
hash2fstree_SOURCES = hash2fstree.c fstree.c fstree.h hashfilelib.c hashfilelib.h

#
#From the old Makefile:
#DEBUG_DEV ?= 0
#DEBUG_FILE_NAMES ?= 0
#DEBUG_CHUNKS ?= 0
#

#
# pass OPT_FLAGS="" or something else to re/set default optimization flags, or add your changes to myopts.mk
#-include myopts.mk
#ifeq ($(OPT_FLAGS),)
#OPT_FLAGS=-O2
#endif
#

#
#CFLAGS=-std=gnu99 -g ${OPT_FLAGS} -Wall -DDEBUG_DEVIATION=${DEBUG_DEV} -DDEBUG_FILES=${DEBUG_FILE_NAMES} \
#			   -DDEBUG_CHUNKS=${DEBUG_CHUNKS}
#			   #

#entropy: entropy.c
#	gcc $(CFLAGS) -lm -o entropy entropy.c
#

#
#
#uniqfilter: uniq_hash_filter.c bloomlib.c bloomlib.h hashfilelib.c hashfilelib.h
#	gcc $(CFLAGS) -lm -o uniqfilter uniq_hash_filter.c bloomlib.c hashfilelib.c
#
#dedup_gen: dedup_gen.c liblog.h liblog.c
#	gcc $(CFLAGS) -o dedup_gen dedup_gen.c liblog.c
#
#simdex: simdex.c hashfilelib.h rbtree.c rbtree.h list.h
#	gcc $(CFLAGS) -o simdex simdex.c rbtree.c hashfilelib.c
#
#fsscan: fsscan.c fstree.c fstree.h
#	gcc $(CFLAGS) -lcrypto -o fsscan fsscan.c fstree.c
#

#fstree-populate: fstree-populate.c fstree.c fstree.h rbtree.c rbtree.h \
#		 hashfilelib.c hashfilelib.h
#
#	gcc $(CFLAGS) -lcrypto -o fstree-populate fstree-populate.c fstree.c \
#				rbtree.c hashfilelib.c
#
