SVA_OBJS += traps.o mem.o

obj-y += $(SVA_OBJS)

# SVA header files include some system headers that aren't normally accessible
# when building Xen, so direct the compilier to our compatibility shims.
$(SVA_OBJS): CFLAGS += -Iinclude/
