/* Fresh inert tasks ONLY. No fabric, host, profile or PID arguments. */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
struct event{char code;int32_t pid,tid;};
static int input_fd,output_fd;
static int futex_word;
static volatile int raw_tid;
static void emit_with(char c,int tid){struct event e={c,getpid(),tid};ssize_t n=write(output_fd,&e,sizeof(e));if(n!=(ssize_t)sizeof(e))_exit(91);}
static void emit(char c){emit_with(c,(int)syscall(SYS_gettid));}
static void usr(int n){(void)n;emit('U');}
static void term(int n){(void)n;emit('T');_exit(0);}
static void *idle(void *a){(void)a;for(;;)pause();return NULL;}
static void *transient(void *a){(void)a;usleep(1500);return NULL;}
static void *churn(void *a){(void)a;for(;;){pthread_t x;if(pthread_create(&x,NULL,transient,NULL))_exit(92);pthread_join(x,NULL);}return NULL;}
static void *futex_waiter(void *a){(void)a;emit('W');for(;;)syscall(SYS_futex,&futex_word,FUTEX_WAIT_PRIVATE,0,NULL,NULL,0);return NULL;}
static int short_raw(void *a){(void)a;struct timespec t={0,1500000};syscall(SYS_nanosleep,&t,NULL);syscall(SYS_exit,0);return 0;}
static void *raw_churn(void *a){
 (void)a;size_t n=131072;void *stack=mmap(NULL,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);if(stack==MAP_FAILED)_exit(87);
 for(;;){raw_tid=0;int flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_UNTRACED|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID;
  int c=clone(short_raw,(char*)stack+n,flags,NULL,(int*)&raw_tid,NULL,(int*)&raw_tid);if(c<0)_exit(88);while(raw_tid)syscall(SYS_futex,&raw_tid,FUTEX_WAIT,c,NULL,NULL,0);
 }
 return NULL;
}
static int outside(void *a){(void)a;emit('O');for(int i=0;i<100;i++)usleep(50000);syscall(SYS_exit,0);return 0;}
static int untraced(void *a){(void)a;emit('I');for(;;)syscall(SYS_pause);return 0;}
static int vfork_child(void *a){(void)a;emit('O');char c;while(read(input_fd,&c,1)<0&&errno==EINTR){}syscall(SYS_exit,0);return 0;}
static int clone_one(int hidden,int thread,int vf){
 size_t size=128*1024;void *stack=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);if(stack==MAP_FAILED)_exit(93);
 int flags=CLONE_VM|(thread?(CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_UNTRACED):0);
 if(hidden){flags|=CLONE_PTRACE|CLONE_UNTRACED;}
 if(vf)flags|=CLONE_VFORK;
 int child=clone(vf?vfork_child:(thread?untraced:outside),(char*)stack+size,flags,NULL);if(child<0)_exit(94);emit_with('B',child);return child;
}
static void *control(void *a){(void)a;char c;
 for(;;){ssize_t n=read(input_fd,&c,1);if(n<0&&errno==EINTR)continue;if(n!=1)_exit(0);
  if(c=='E'){char x[24],y[24];snprintf(x,sizeof(x),"%d",input_fd);snprintf(y,sizeof(y),"%d",output_fd);execl("/proc/self/exe","inert-after-exec","--after",x,y,(char*)NULL);_exit(95);}
  else if(c=='H')clone_one(1,0,0);else if(c=='C')clone_one(0,0,0);else if(c=='I')clone_one(0,1,0);else if(c=='V')clone_one(0,0,1);else if(c=='Q')_exit(0);
 }
 return NULL;
}
int main(int argc,char **argv){
 if(argc!=4){return 80;}
 input_fd=atoi(argv[2]);output_fd=atoi(argv[3]);alarm(25);if(prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0))return 81;
 struct sigaction a={0};a.sa_handler=usr;sigemptyset(&a.sa_mask);if(sigaction(SIGUSR1,&a,NULL))return 82;
 if(!strcmp(argv[1],"--after")){emit('E');char c;for(;;){ssize_t n=read(input_fd,&c,1);if(n==1&&c=='Q')return 0;if(n<0&&errno==EINTR)continue;if(n<=0)return 0;}}
 if(!strcmp(argv[1],"term-handler")){a.sa_handler=term;if(sigaction(SIGTERM,&a,NULL))return 83;}
 pthread_t worker;if(pthread_create(&worker,NULL,control,NULL))return 84;
 if(!strcmp(argv[1],"futex")){pthread_t x;if(pthread_create(&x,NULL,futex_waiter,NULL))return 87;}
 if(!strcmp(argv[1],"untraced-churn")){pthread_t x;if(pthread_create(&x,NULL,raw_churn,NULL))return 88;}
 if(!strcmp(argv[1],"churn")){pthread_t x;if(pthread_create(&x,NULL,churn,NULL))return 85;}
 if(!strcmp(argv[1],"many")){pthread_attr_t attr;pthread_attr_init(&attr);pthread_attr_setstacksize(&attr,65536);for(int i=0;i<260;i++){pthread_t x;if(pthread_create(&x,&attr,idle,NULL))return 86;}pthread_attr_destroy(&attr);}
 emit('R');for(;;)pause();
}
