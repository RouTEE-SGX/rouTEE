#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8202

#define SCRIPTS_PATH  "./scripts/"

int client_socket;
struct sockaddr_in server_address;
unsigned char Buff[250];
int read_len;

void send_script(char* script_name) {

  /* Open the file for reading */
  char *client_msg = NULL;
  size_t client_msg_size = 0;
  int line_count = 0;
  ssize_t line_size;

  char *path_to_script = malloc(strlen(SCRIPTS_PATH) + strlen(script_name) + 1);
  strcpy(path_to_script, SCRIPTS_PATH);
  strcat(path_to_script, script_name);

  FILE *fp = fopen(path_to_script, "r");
  if (!fp)
  {
    fprintf(stderr, "Error: opening file '%s'\n", path_to_script);
    return;
  }

  printf("\nrun script %s\n\n", script_name);
  clock_t begin = clock();
  while(1) {

    // get a line from a file 
    line_size = getline(&client_msg, &client_msg_size, fp);
    if (line_size < 0) {
      clock_t end = clock();
      double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
      printf("finish the script %s (execution time: %d microsec = %.3f millisec = %f sec)\n\n", script_name, (int)(time_spent*1000000), time_spent*1000, time_spent);
      return;
    }
    printf("script command: %s", client_msg);

    // send command
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

    // if get fail response from server
    if (strcmp(Buff, "SUCCESS") != 0) {
      printf("script command failed\n\n");
      return;
    }

  }

}

int main(void) {

  client_socket = socket(PF_INET,SOCK_STREAM,0);
  if (client_socket == -1) {
    printf("Client Socket ERROR");
    exit(0);
  }
  bzero((char*)&server_address, sizeof(server_address));

  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
  server_address.sin_port = htons(SERVER_PORT);

  if(connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
    printf("Connect ERROR");
    exit(0);
  }
  printf("\nyou are connected! client socket = [%d]\n\n",client_socket);
  
  char client_msg[300000];
  while (1) {
    // send a command
    printf("input cmd: ");
    gets(client_msg);
    if ((uint32_t)strlen(client_msg) == 0) {
      continue;
    }

    // got script name (script name should start with 's')
    if (client_msg[0] == 's') {
      // run script
      send_script(client_msg);
      continue;
    }

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
