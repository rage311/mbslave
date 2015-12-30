#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
  #include <arpa/inet.h>
#else
  #include <Ws2tcpip.h>
  /*#include <winsock2.h>*/
#endif

#include <modbus/modbus.h>


/* checks to see if a char* IP address can be parsed as */
/* a proper IP address */
int is_valid_ip(char *ip_addr)
{
  struct sockaddr_in sa;
#ifdef _WIN32
  return (inet_addr(ip_addr) != INADDR_NONE);
#else
  return inet_pton(AF_INET, ip_addr, &(sa.sin_addr));
#endif
}

int main(int argc, char **argv)
{
  modbus_t *ctx;
  uint8_t req[MODBUS_TCP_MAX_ADU_LENGTH];
  int req_len;
  int reply_len;
  modbus_mapping_t *mb_mapping;
  int i;

  int s = -1;
  int port = 502;
  char ip_addr[16] = { '\0' };

  if (argc == 2) {
    strncpy(ip_addr, argv[1], 15);// = argv[1];//"192.168.155.197";
  } else if (argc == 1) {
    strncpy(ip_addr, "127.0.0.1", 9);
  }

  if (!is_valid_ip(ip_addr)) {
    fprintf(stderr, "Invalid IP address argument.\n");
    exit(EXIT_FAILURE);
  }

  mb_mapping = modbus_mapping_new(0, 0, 20000, 0);
  if (!mb_mapping) {
    fprintf(stderr, "Failed to allocate the modbus map: %s\n",
            modbus_strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* set some default values */
  for (i = 0; i < 10; i++) {
    mb_mapping->tab_registers[i] = (uint16_t)i;
  }

  ctx = modbus_new_tcp(ip_addr, port);
  if (!ctx) {
    fprintf(stderr, "Unable to allocate libmodbus context.\n");
    exit(EXIT_FAILURE);
  }
  modbus_set_debug(ctx, 1);

  s = modbus_tcp_listen(ctx, 5);

  while (1) {
    printf("listening on %s:%d...\n", ip_addr, port);
    modbus_tcp_accept(ctx, &s);
    puts("accepted");

    do {
      req_len = modbus_receive(ctx, req);

      printf("req_len: %d\n", req_len);

      if (req_len > 0) {
        printf("rx: ");
        for (i = 0; i < req_len; i++) {
          if (i > 0 && i % 2 == 0) {
            printf(" ");
          }
          printf("%.2x", req[i]);
        }
        printf("\n\n");
        reply_len = modbus_reply(ctx, req, req_len, mb_mapping);
      }
    } while (req_len > 0); 

    printf("errno: %s\n", modbus_strerror(errno));
  }

  if (s != -1) {
    close(s);
  }

  modbus_mapping_free(mb_mapping);
  modbus_close(ctx);
  modbus_free(ctx);

  return 0;
}

