/*
 * gcc nued_ssh.c -I/usr/local/include -L/usr/local/lib -lssh -o nued_ssh
 * nued ssh client - Written by nue - 12.2o13
 * irc.oftc.net #nerds
 */
#define LIBSSH_STATIC 1
#define MAX_LEN 256
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <openssl/blowfish.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

void die(ssh_session sesh, ssh_channel chan){
  if(chan){
    ssh_channel_close(chan); // Clean up the channel.
    ssh_channel_send_eof(chan);
    ssh_channel_free(chan);
  }
  ssh_disconnect(sesh); // Close the ssh session.
  ssh_free(sesh);
  exit(0);
}
void usage(char *pro){
  fprintf(stderr, "Usage is: %s user@host:[port]\n", pro);
  fprintf(stderr, "+ username and host are required\n");
  fprintf(stderr, "- port will default to 22 if not supplied\n");
  exit(-1);
}
int main(int argc, char **argv){
	int x, port = 0;
	char user[MAX_LEN] = {0}; // Check RCF for max lengths???
	char hostname[MAX_LEN] = {0};
	char *pass, buffer[MAX_LEN], *pos;
  fd_set SSH_fd; // File descriptor objects for reading/writing.
  struct timeval timeSig; // Timeout objects.
  ssh_session nueb_ssh;
  ssh_channel nueb_chan;

  if(argc != 2) usage(argv[0]); // Check for number of arguments.

  if(!(strstr(argv[1], "@"))) usage(argv[0]); // Check for syntax.
  pos = argv[1];

  for(x=0;*pos && *pos != '@';pos++,x++){} // Push little pointer, push!
  strncpy(user, argv[1], (x>=MAX_LEN)?MAX_LEN-1:x); // Copy the username.
  argv[1] = ++pos; // Go past '@'
  
  for(x=0;*pos && *pos != ':';pos++,x++){} // Pushed again, you little bitch.
  strncpy(hostname, argv[1], (x>=MAX_LEN)?MAX_LEN-1:x); // Copy the hostname.
  if(*pos++ == ':' && *pos) port = atoi(pos); // Calculate the port.
  if(!port) port=22; // Maybe the user entered non-digits, so default.
  
  nueb_ssh = ssh_new(); // Make a new ssh object.
  if(!nueb_ssh) exit(-1); // Die if the object couldn't be made.
  ssh_options_set(nueb_ssh, SSH_OPTIONS_HOST, hostname); // Set hostname.
  ssh_options_set(nueb_ssh, SSH_OPTIONS_PORT, &port); // Set the port.
  ssh_options_set(nueb_ssh, SSH_OPTIONS_USER, user); // Set the username.

  if(ssh_connect(nueb_ssh) != SSH_OK) die(nueb_ssh, NULL); // Connect to the session or die.
  while(ssh_userauth_kbdint(nueb_ssh, NULL, NULL) != SSH_AUTH_SUCCESS){ // Keyboard interactive!
    port = ssh_userauth_kbdint_getnprompts(nueb_ssh);
    for(x=0;x<port;x++) // Send the password to the server.
      if(ssh_userauth_kbdint_setanswer(nueb_ssh, x, getpass(ssh_userauth_kbdint_getprompt(nueb_ssh, x, NULL))) < 0) die(nueb_ssh, NULL);
  }

  if(!(nueb_chan = ssh_channel_new(nueb_ssh))) die(nueb_ssh, NULL); // Make a channel.
  if(ssh_channel_open_session(nueb_chan) != SSH_OK) die(nueb_ssh, nueb_chan); // Open a channel session.
  if(ssh_channel_request_pty(nueb_chan) != SSH_OK) die(nueb_ssh, nueb_chan); // Open a pty (terminal).
  if(ssh_channel_change_pty_size(nueb_chan, 80, 24) != SSH_OK) die(nueb_ssh, nueb_chan); // ASSUME the window size.
  if(ssh_channel_request_shell(nueb_chan) != SSH_OK) die(nueb_ssh, nueb_chan); // FINALLY get a shell.
 
  while(ssh_channel_is_open(nueb_chan) && !ssh_channel_is_eof(nueb_chan)){
    timeSig.tv_sec = 30;
    timeSig.tv_usec = 0;
    ssh_channel in_chan[2], out_chan[2];
 
    in_chan[0] = nueb_chan;
    in_chan[1] = NULL;
 
    FD_ZERO(&SSH_fd); // Make a little mutex, and read/write to the pty. :E
    FD_SET(0, &SSH_fd);
    FD_SET(ssh_get_fd(nueb_ssh), &SSH_fd);
    ssh_select(in_chan, out_chan, ssh_get_fd(nueb_ssh)+1, &SSH_fd, &timeSig);
 
    if(out_chan[0]){
      x = ssh_channel_read(nueb_chan, buffer, MAX_LEN, 0);
      if(x<0) die(nueb_ssh, nueb_chan);
      if(x>0)
        if(write(1, buffer, x) != x) die(nueb_ssh, nueb_chan);
    }
    if(FD_ISSET(0, &SSH_fd)){
      x = read(0, buffer, MAX_LEN);
      if(x<0) die(nueb_ssh, nueb_chan);  
      if(x>0)
        if(ssh_channel_write(nueb_chan, buffer, x) != x) die(nueb_ssh, nueb_chan);
    }
  }
  die(nueb_ssh, nueb_chan);
  return 0; // Awww. Never reached.
}
