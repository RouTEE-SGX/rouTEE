#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7223

int main(void) {

  int client_socket;
  struct sockaddr_in server_address;
  unsigned char Buff[250];
  int read_len; 

  client_socket = socket(PF_INET,SOCK_STREAM,0);
  if (client_socket == -1) {
    printf("Client Socket ERROR");
    exit(0);
  }
  bzero((char *)&server_address, sizeof(server_address));

  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
  server_address.sin_port = htons(SERVER_PORT);

  if(connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
    printf("Connect ERROR");
    exit(0);
  }
  printf("\nyou are connected! client socket = [%d]\n\n",client_socket);
  
  char client_msg[30];
  while (1) {
    // send a command
    printf("input cmd: ");
    gets(client_msg);
    if(send(client_socket, client_msg, strlen(client_msg), 0) < 0){
      printf("send error");
    }

    // get response from the server
    read_len = read(client_socket, Buff, sizeof(Buff));
    if (client_socket == -1) {
      printf("Disconnection Check\n");
      close(client_socket);
      break;
    }
    Buff[read_len] = '\0';
    printf(">> server response: %s\n\n",Buff);
  }

  close(client_socket);

  return 0;
}
