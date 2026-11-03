/* Fixture-only inherited disposition / own seccomp restriction launcher. */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(int argc,char **argv){
 if(argc<3)return 90;
 struct sigaction a={0};sigemptyset(&a.sa_mask);a.sa_handler=SIG_IGN;a.sa_flags=SA_NOCLDWAIT;if(!strcmp(argv[1],"ignored")&&sigaction(SIGCHLD,&a,NULL))return 91;
 if(!strcmp(argv[1],"ignored-alarm")){a.sa_handler=SIG_IGN;a.sa_flags=0;if(sigaction(SIGALRM,&a,NULL))return 94;}
 if(!strcmp(argv[1],"blocked-alarm")){sigset_t s;sigemptyset(&s);sigaddset(&s,SIGALRM);if(sigprocmask(SIG_BLOCK,&s,NULL))return 95;}
 if(!strcmp(argv[1],"deny")){
  struct sock_filter f[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ptrace,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
  struct sock_fprog p={(unsigned short)(sizeof(f)/sizeof(f[0])),f};if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p))return 92;
 }
 execv(argv[2],argv+2);return 93;
}
