CTID=ctid.so

ctid: $(CTID)

ctid.so : sm_ctid.c
	$(CC) -shared -fPIC -lgmssl -Iusr/local/include/gmssl -llua -ldl -o $@ $?