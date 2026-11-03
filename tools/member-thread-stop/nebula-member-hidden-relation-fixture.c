/* OWN disposable subreaper/tracer/target/autochild only. No target PID input.
 * Demonstrates unobserved auto-relationship cleanup; does not claim a zero-result
 * wait would prove the child unscheduled. The tracer never waits for that child.
 */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
struct event{char code;int32_t a,b;};
static int target_cmd[2],outside_cmd[2],local_event[2],observe[2],go[2];
static void send_event(int fd,char c,int a,int b){struct event e={c,a,b};if(write(fd,&e,sizeof(e))!=(ssize_t)sizeof(e))_exit(91);}
static int receive(int fd,struct event *e){struct pollfd p={fd,POLLIN,0};return poll(&p,1,3000)==1&&read(fd,e,sizeof(*e))==(ssize_t)sizeof(*e);}
static int tracer_pid(pid_t p){char path[80],line[1024];snprintf(path,sizeof(path),"/proc/%ld/status",(long)p);FILE *f=fopen(path,"r");if(!f)return -1;int v=-1;while(fgets(line,sizeof(line),f))if(sscanf(line,"TracerPid: %d",&v)==1)break;fclose(f);return v;}
static int outside(void *a){(void)a;alarm(8);send_event(observe[1],'O',getpid(),0);char c;ssize_t n;do{n=read(outside_cmd[0],&c,1);}while(n<0&&errno==EINTR);syscall(SYS_exit,n==1&&c=='Q'?0:92);return 0;}
static void target(void){
 alarm(10);send_event(local_event[1],'R',getpid(),0);char c;if(read(target_cmd[0],&c,1)!=1||c!='H')_exit(93);
 void *p=mmap(NULL,131072,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);if(p==MAP_FAILED)_exit(94);
 int child=clone(outside,(char*)p+131072,CLONE_VM|CLONE_PTRACE|CLONE_UNTRACED|SIGCHLD,NULL);if(child<0)_exit(95);send_event(local_event[1],'B',child,0);
 ssize_t n;do{n=read(target_cmd[0],&c,1);}while(n<0&&errno==EINTR);_exit(n==1&&c=='Q'?0:96);
}
static void trace(void){
 alarm(8);pid_t p=fork();if(p<0)_exit(80);if(!p)target();struct event e;if(!receive(local_event[0],&e)||e.code!='R'||e.a!=p)_exit(81);
 if(ptrace(PTRACE_SEIZE,p,0,(void*)(uintptr_t)(PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT)))_exit(82);
 if(write(target_cmd[1],"H",1)!=1||!receive(local_event[0],&e)||e.code!='B'){_exit(83);}
 int child=e.a;
 if(ptrace(PTRACE_INTERRUPT,p,0,0)){_exit(84);}
 siginfo_t si;memset(&si,0,sizeof(si));long long attempts=0;
 do{if(waitid(P_PID,p,&si,WSTOPPED|WEXITED|WNOWAIT|WNOHANG|__WALL))_exit(85);if(si.si_pid)break;usleep(1000);}while(++attempts<1000);
 if(si.si_pid!=p||si.si_code!=CLD_TRAPPED||si.si_status!=(SIGTRAP|(PTRACE_EVENT_STOP<<8)))_exit(86);
 send_event(observe[1],'P',p,child);char c;if(read(go[0],&c,1)!=1||c!='G')_exit(87);
 /* No child wait, DETACH, signal or termination. exit_ptrace unlinks unknown. */
 _exit(0);
}
int main(void){
 int original=0;if(prctl(PR_GET_CHILD_SUBREAPER,&original)||prctl(PR_SET_CHILD_SUBREAPER,1))return 70;
 if(pipe(target_cmd)||pipe(outside_cmd)||pipe(local_event)||pipe(observe)||pipe(go))return 71;
 pid_t tracer=fork();if(tracer<0)return 72;if(!tracer)trace();int tf=(int)syscall(SYS_pidfd_open,tracer,0),pf=-1,cf=-1;struct event e;int good=0;pid_t parent=0,child=0;
 if(tf<0||!receive(observe[0],&e)||e.code!='P'){goto cleanup;}
 parent=e.a;child=e.b;pf=(int)syscall(SYS_pidfd_open,parent,0);cf=(int)syscall(SYS_pidfd_open,child,0);
 if(pf<0||cf<0||tracer_pid(parent)!=tracer||tracer_pid(child)!=tracer)goto cleanup;
 if(write(go[1],"G",1)!=1){goto cleanup;}
 int s=0;if(waitpid(tracer,&s,0)!=tracer||!WIFEXITED(s)||WEXITSTATUS(s))goto cleanup;
 if(!receive(observe[0],&e)||e.code!='O'||e.a!=child||tracer_pid(parent)!=0||tracer_pid(child)!=0)goto cleanup;
 if(write(target_cmd[1],"Q",1)!=1||write(outside_cmd[1],"Q",1)!=1)goto cleanup;
 int ps=0,cs=0;if(waitpid(parent,&ps,__WALL)!=parent||waitpid(child,&cs,__WALL)!=child||!WIFEXITED(ps)||WEXITSTATUS(ps)||!WIFEXITED(cs)||WEXITSTATUS(cs))goto cleanup;good=1;
cleanup:
 if(!good){int fds[]={cf,pf,tf};for(int i=0;i<3;i++)if(fds[i]>=0)syscall(SYS_pidfd_send_signal,fds[i],SIGKILL,NULL,0);}
 int fds[]={cf,pf,tf};for(int i=0;i<3;i++)if(fds[i]>=0)close(fds[i]);prctl(PR_SET_CHILD_SUBREAPER,original);
 printf("{\"status\":\"%s\",\"parent_clone_event_absent\":%s,\"outside_auto_relationship_never_waited_or_detached\":%s,\"kernel_tracer_exit_unlinked_both\":%s,\"both_inert_children_exited_normally\":%s,\"numeric_sigterm_sent\":false,\"zero_wait_implies_unscheduled_claimed\":false,\"production_targets_used\":false}\n",good?"passed":"refused",good?"true":"false",good?"true":"false",good?"true":"false",good?"true":"false");return good?0:1;
}
