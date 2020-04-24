#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <modbus/modbus.h>

#ifdef _WIN32
  #include <Ws2tcpip.h>
  /*#include <winsock2.h>*/
#else
  #include <arpa/inet.h>
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__)
  #include <sys/socket.h>
  #include <netinet/in.h>
#endif

#ifndef _WIN32
  extern const char *__progname;
#else
  const char *__progname;
#endif


#define MODBUS_TCP_DEFAULT_PORT 502


/* print usage */
void usage()
{
  printf("Usage: %s [option]\n", __progname);
  puts("MODBUS/TCP Slave\n");

  puts("  -h    show this usage");
  puts("  -p    listen port number (optional -- default 502)");
}


void cleanup(modbus_t *ctx, modbus_mapping_t *mb_mapping) {
  modbus_mapping_free(mb_mapping);
  modbus_close(ctx);
  modbus_free(ctx);
}

typedef enum {
  S_SHORT,
  S_LONG,
  U_SHORT,
  U_LONG,
  BINARY,
  FLOAT_T,
  ASCII
} format_type;

struct modbus_db_params {
  int starting_register;
  int num_registers;
  format_type format;
};

struct modbus_comm_params {
  char *ip_address;
  int port;
  int response_timeout;
  int rtu_address;
  int slave;
};


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


int parse_args(struct modbus_comm_params *mbcp, struct modbus_db_params *mbdp,
               int argc, char **argv)
{
  int port = MODBUS_TCP_DEFAULT_PORT;
  int current_arg = -1;

  /* parse flags */
  while ((current_arg = getopt(argc, argv, "hp:")) != -1) {
    switch (current_arg) {
      case 'h':
        usage();
        exit(EXIT_SUCCESS);
      case 'p':
        mbcp->port = atoi(optarg);
        port = mbcp->port;
        break;
      case '?':
        if (optopt == 'p') {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        }
        else {
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        }
        exit(EXIT_FAILURE);
      default:
        exit(EXIT_FAILURE);
    }
  }

  return port;
}


int main(int argc, char **argv) {
  modbus_t *ctx;
  int req_len, _reply_len;
  modbus_mapping_t *mb_mapping;
  int i;

  struct modbus_comm_params mbcp;
  struct modbus_db_params mbdp;

  int s = -1;
  int port = parse_args(&mbcp, &mbdp, argc, argv);
  char ip_addr[16] = { "0.0.0.0" };

  /* TODO: take cli args */
  /* if (argc == 2) { */
  /*   strncpy(ip_addr, argv[1], 15); */
  /* } else if (argc == 1) { */
  /*   strncpy(ip_addr, "0.0.0.0", 9); */
  /* } */

  if (!is_valid_ip(ip_addr)) {
    fprintf(stderr, "Invalid IP address argument.\n");
    exit(EXIT_FAILURE);
  }

  mb_mapping = modbus_mapping_new(0, 0, 10000, 0);
  if (!mb_mapping) {
    fprintf(stderr, "Failed to allocate the modbus map: %s\n",
            modbus_strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* set some default values */
  for (i = 0; i < 10000; i++) {
    mb_mapping->tab_registers[i] = (uint16_t)i % 1000;
  }

  ctx = modbus_new_tcp(ip_addr, port);
  if (!ctx) {
    fprintf(stderr, "Unable to allocate libmodbus context.\n");
    modbus_mapping_free(mb_mapping);
    exit(EXIT_FAILURE);
  }

  s = modbus_tcp_listen(ctx, 5);
  printf("Listening on %s:%d...\n\n", ip_addr, port);

  for (;;) {
    uint8_t req[MODBUS_TCP_MAX_ADU_LENGTH];

    modbus_set_debug(ctx, 1);
    if (modbus_tcp_accept(ctx, &s) == -1) {
      printf("errno: %s\n", modbus_strerror(errno));
      if (port < 1024 && getuid() > 0) {
        puts("HINT: Using a port below 1024 requires elevated privileges.");
      }
      cleanup(ctx, mb_mapping);
      exit(EXIT_FAILURE);
    }
    modbus_set_debug(ctx, 0);

    req_len = modbus_receive(ctx, req);

    if (req_len > 0) {
      printf("rx:");
      for (i = 0; i < req_len; i++) {
        printf("%s%.2x", i > 0 && i % 2 ? "" : " ", req[i]);
      }
      puts("\n");
      _reply_len = modbus_reply(ctx, req, req_len, mb_mapping);
    }

    if (errno != 0 && errno != ECONNRESET) {
      printf("errno string: %s\n", modbus_strerror(errno));
    }
    modbus_close(ctx);
  }

  if (s != -1) {
    close(s);
  }

  cleanup(ctx, mb_mapping);

  return EXIT_SUCCESS;
}

