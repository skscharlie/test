GCC := gcc

TARGET := tmptest

SSL_CLIENT := ssl_client
SSL_SERVER := ssl_server 

OBJS += test.o

all: ${TARGET}

./%.o: ./%.c
	${GCC}  -c -o "$@" "$<" `pkg-config json-c --cflags` 

${TARGET}: ${OBJS}
	${GCC} ${OBJS} -o ${TARGET} `pkg-config json-c --libs` `pkg-config openssl --libs` -lsqlite3

${SSL_CLIENT} : ssl_client.o  
	${GCC} ssl_client.o -o ${SSL_CLIENT} `pkg-config openssl --libs`

${SSL_SERVER} : ssl_server.o 
	${GCC} ssl_server.o -o ${SSL_SERVER} `pkg-config openssl --libs`