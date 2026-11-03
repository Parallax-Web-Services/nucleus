/* SOURCE ONLY: schema2 all-thread legacy-member stop candidate.
 * No installed helper replacement, host ptrace permission, pidfd equivalence,
 * executable behavior provenance or operational authorization is implied.
 * Native identity/Load validation remains an explicit fresh caller prerequisite.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/file.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#include <poll.h>
#define MAX_TASKS 256
#define MAX_EVENTS 1024
#define ACQUIRE_MS 3000
#define PRIVATE_MS 2000
#define CLEANUP_MS 1000
#define WHOLE_MS 8000
#define OPTIONS (PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT)
struct plan { unsigned long long pid,start,uid,gid,exe_dev,exe_ino,exe_size,checked_at,valid_until,native_load_preflight; char state[PATH_MAX]; };
struct proc { unsigned long long start,pending,shared; unsigned uid[4],gid[4]; int tracer,tgid,pid,threads; char state; };
struct held { pid_t tid; unsigned long long start; int stopped,event,signal; unsigned long child; int initial; };
static struct held tasks[MAX_TASKS];
static size_t task_count;
static unsigned event_count;
static volatile sig_atomic_t cancelled,watch_phase;
static const char *failure="unclassified";
static long long whole_deadline,private_deadline;
static int outside_observed,final_accepted,queued,detach_count,cleanup_partial;
static long long now_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return (long long)t.tv_sec*1000+t.tv_nsec/1000000;}
static int within(long long deadline){long long n=now_ms();return !cancelled&&n>=0&&n<=deadline&&n<=whole_deadline;}
static void cancel(int n){(void)n;cancelled=1;}
/* Never perform possibly blocking output from the watchdog. The caller must
 * treat silent exit124 as incomplete evidence and must never replay a queue. */
static void hard_timeout(int n){(void)n;_exit(124);}
static int arm_budget(int milliseconds,int phase){
 long long left=whole_deadline-now_ms();if(left<milliseconds)milliseconds=(int)left;if(milliseconds<=0)return 0;
 struct itimerval t;memset(&t,0,sizeof(t));t.it_value.tv_sec=milliseconds/1000;t.it_value.tv_usec=(milliseconds%1000)*1000;watch_phase=phase;return setitimer(ITIMER_REAL,&t,NULL)==0;
}
#define NEED(v,label) do{if(!(v)){failure=(label);goto refused;}}while(0)
static int same(struct stat *a,struct stat *b) {
 return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int protected_path(const char *path) {
 char real[PATH_MAX],copy[PATH_MAX]; struct stat s;
 if(lstat("/",&s)||!S_ISDIR(s.st_mode)||s.st_uid!=0||(s.st_mode&0022))return 0;
 if(!realpath(path,real)||strcmp(real,path)||strlen(path)>=sizeof(copy))return 0;
 strcpy(copy,path);
 for(char *c=copy+1;;c++)if(*c=='/'||!*c){ char saved=*c;*c=0;
  if(lstat(copy,&s)||s.st_uid!=0||(s.st_mode&0022)||S_ISLNK(s.st_mode))return 0;
  *c=saved;if(!saved)break;
 }
 return 1;
}
static int private_file(const char *path,mode_t mode,size_t maximum,struct stat *held) {
 int fd;struct stat a;
 if(!protected_path(path)||(fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC))<0)return -1;
 if(fstat(fd,held)||lstat(path,&a)||!same(held,&a)||!S_ISREG(held->st_mode)||held->st_uid||held->st_gid||(held->st_mode&07777)!=mode||held->st_nlink!=1||held->st_size<0||(uint64_t)held->st_size>maximum){close(fd);return -1;}
 return fd;
}
static int unchanged(int fd,const char *path,struct stat *before) {
 struct stat a,b;return fstat(fd,&a)==0&&lstat(path,&b)==0&&same(before,&a)&&same(before,&b);
}
static int unchanged_lock(int fd,const char *path,struct stat *before) {
 struct stat a,b;if(fstat(fd,&a)||lstat(path,&b))return 0;
 return S_ISREG(a.st_mode)&&a.st_dev==before->st_dev&&a.st_ino==before->st_ino&&a.st_mode==before->st_mode&&a.st_uid==before->st_uid&&a.st_gid==before->st_gid&&a.st_nlink==1&&a.st_size==0&&b.st_dev==a.st_dev&&b.st_ino==a.st_ino&&b.st_mode==a.st_mode&&b.st_uid==a.st_uid&&b.st_gid==a.st_gid&&b.st_nlink==1&&b.st_size==0;
}
static int compare_fds(int a,int b,size_t maximum) {
 char x[8192],y[8192];off_t off=0;struct stat sa,sb,aa,bb;
 if(fstat(a,&sa)||fstat(b,&sb)||sa.st_size!=sb.st_size||sa.st_size<0||(uint64_t)sa.st_size>maximum)return 0;
 while(off<sa.st_size){if(!within(private_deadline))return 0;size_t n=(size_t)(sa.st_size-off);if(n>sizeof(x))n=sizeof(x);ssize_t na=pread(a,x,n,off),nb=pread(b,y,n,off);if(na!=(ssize_t)n||nb!=na||memcmp(x,y,n))return 0;off+=na;}
 return !fstat(a,&aa)&&!fstat(b,&bb)&&same(&sa,&aa)&&same(&sb,&bb);
}

static int number(const char *s,unsigned long long *v){char *end;if(!*s)return 0;for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return 0;errno=0;*v=strtoull(s,&end,10);return !errno&&!*end;}
static int fields(const char *s,unsigned long long *v,int count,int hex){
 for(int i=0;i<count;i++){
  while(*s==' '||*s=='\t'){s++;}
  const char *a=s;size_t n=0;
  while((hex&&((*s>='a'&&*s<='f')||(*s>='A'&&*s<='F')))||(*s>='0'&&*s<='9')){s++;n++;}
  if(!n||n>(hex?16U:20U)){return 0;}
  char b[22];memcpy(b,a,n);b[n]=0;char *e;errno=0;v[i]=strtoull(b,&e,hex?16:10);if(errno||*e)return 0;
 }
 while(*s==' '||*s=='\t'){s++;}
 return !*s||(*s=='\n'&&!s[1]);
}
static int process(pid_t tid,struct proc *p){
 memset(p,0,sizeof(*p));char path[80],b[16384],*q,*save,*tok;FILE *f;size_t n;int have=0,stat_ok=0;unsigned long long vals[4];
 snprintf(path,sizeof(path),"/proc/%ld/stat",(long)tid);f=fopen(path,"re");if(!f)return 0;n=fread(b,1,sizeof(b)-1,f);int bad=ferror(f)||!feof(f);fclose(f);if(bad||!n||memchr(b,0,n))return 0;b[n]=0;q=strchr(b,' ');if(!q)return 0;*q=0;unsigned long long pid;if(!number(b,&pid)||pid!=(unsigned long long)tid)return 0;*q=' ';q=strrchr(q,')');if(!q||q[1]!=' ')return 0;
 q+=2;tok=strtok_r(q," \n",&save);for(int k=3;tok;k++,tok=strtok_r(NULL," \n",&save)){if(k==3){if(tok[1]||!strchr("RSDTtZXIPWK",tok[0]))return 0;p->state=tok[0];}if(k==22){if(!number(tok,&p->start)||!p->start)return 0;stat_ok=1;break;}}if(!stat_ok)return 0;
 snprintf(path,sizeof(path),"/proc/%ld/status",(long)tid);f=fopen(path,"re");if(!f)return 0;
 while(fgets(b,sizeof(b),f)){
  if(!strchr(b,'\n')){fclose(f);return 0;}
  const char *s=NULL;int bit=0,count=1,hex=0;
  if(!strncmp(b,"Uid:",4)){s=b+4;bit=1;count=4;}
  else if(!strncmp(b,"Gid:",4)){s=b+4;bit=2;count=4;}
  else if(!strncmp(b,"TracerPid:",10)){s=b+10;bit=4;}
  else if(!strncmp(b,"Tgid:",5)){s=b+5;bit=8;}
  else if(!strncmp(b,"Pid:",4)){s=b+4;bit=16;}
  else if(!strncmp(b,"Threads:",8)){s=b+8;bit=32;}
  else if(!strncmp(b,"SigPnd:",7)){s=b+7;bit=64;hex=1;}
  else if(!strncmp(b,"ShdPnd:",7)){s=b+7;bit=128;hex=1;}
  if(!s){continue;}
  if((have&bit)||!fields(s,vals,count,hex)){fclose(f);return 0;}have|=bit;
  if(bit==1||bit==2){for(int i=0;i<4;i++){if(vals[i]>UINT_MAX){fclose(f);return 0;}(bit==1?p->uid:p->gid)[i]=(unsigned)vals[i];}}
  else if(bit==64)p->pending=vals[0];else if(bit==128)p->shared=vals[0];
  else{if(vals[0]>INT_MAX){fclose(f);return 0;}if(bit==4)p->tracer=(int)vals[0];if(bit==8)p->tgid=(int)vals[0];if(bit==16)p->pid=(int)vals[0];if(bit==32)p->threads=(int)vals[0];}
 }
 bad=ferror(f);fclose(f);return !bad&&have==255&&p->pid==tid&&p->tgid>1&&p->threads>0;
}
static int task_identity(pid_t tid,unsigned long long start,const struct plan *v,int tracer,int exe,const struct stat *before,struct proc *out,int pending_allowed){
 struct proc p;char path[80];struct stat a,b;
 if(!process(tid,&p)||p.start!=start||p.tracer!=tracer||p.tgid!=(pid_t)v->pid||p.state=='Z'||p.state=='X'||(!pending_allowed&&(p.pending||p.shared)))return 0;
 for(int i=0;i<4;i++)if(p.uid[i]!=v->uid||p.gid[i]!=v->gid)return 0;
 snprintf(path,sizeof(path),"/proc/%ld/exe",(long)tid);if(stat(path,&a)||fstat(exe,&b)||!same((struct stat*)before,&a)||!same((struct stat*)before,&b))return 0;if(out)*out=p;return 1;
}
static int parse(int fd,struct plan *p){
 memset(p,0,sizeof(*p));char b[8193],*save,*line;struct stat s;ssize_t n=pread(fd,b,sizeof(b)-1,0);if(fstat(fd,&s)||n!=s.st_size||n<=0||n>8192||memchr(b,0,(size_t)n)||b[n-1]!='\n')return 0;b[n]=0;if(strstr(b,"\n\n")||strchr(b,'\r'))return 0;
 const char *keys[]={"schema","pid","start","uid","gid","exe_dev","exe_ino","exe_size","checked_at","valid_until","native_load_preflight","state"};unsigned long long *vs[]={NULL,&p->pid,&p->start,&p->uid,&p->gid,&p->exe_dev,&p->exe_ino,&p->exe_size,&p->checked_at,&p->valid_until,&p->native_load_preflight};
 line=strtok_r(b,"\n",&save);for(int i=0;i<12;i++,line=strtok_r(NULL,"\n",&save)){
  if(!line||strlen(line)<=strlen(keys[i])||strncmp(line,keys[i],strlen(keys[i]))||line[strlen(keys[i])]!='='){return 0;}
  char *v=line+strlen(keys[i])+1;
  if(i==0){if(strcmp(v,"2"))return 0;}else if(i==11){if(*v!='/'||strlen(v)>=sizeof(p->state))return 0;strcpy(p->state,v);}else if(!number(v,vs[i]))return 0;
 }
 unsigned long long ntime=(unsigned long long)time(NULL);return !line&&p->pid>1&&p->pid<=INT_MAX&&p->start&&p->uid==0&&p->gid==0&&p->exe_size&&p->exe_size<=64*1024*1024&&p->checked_at<=ULLONG_MAX-120&&p->valid_until==p->checked_at+120&&p->checked_at<=ntime&&ntime<=p->valid_until&&p->native_load_preflight==1;
}
static int namespace_ok(const char *path){
#ifdef NEBULA_THREAD_STOP_FIXTURE
 const char *prefix="/run/nebula-member-thread-test-";size_t n=strlen(prefix);if(strncmp(path,prefix,n))return 0;const char *p=strchr(path+n,'/');if(!p||p==path+n)return 0;path=p;
#else
 const char *prefix="/var/lib/parallax-nebula-member-migration";size_t n=strlen(prefix);if(strncmp(path,prefix,n))return 0;path+=n;
#endif
 const char *pfx="/thread-stop-";size_t k=strlen(pfx);if(strncmp(path,pfx,k)||strlen(path)!=k+16+13)return 0;for(int i=0;i<16;i++)if(!((path[k+i]>='a'&&path[k+i]<='f')||(path[k+i]>='0'&&path[k+i]<='9')))return 0;return !strcmp(path+k+16,"/stop.request");
}
#ifdef NEBULA_THREAD_STOP_FIXTURE
static void hook(const char *stage){
 const char *a=getenv("NEBULA_TEST_IN"),*b=getenv("NEBULA_TEST_OUT");if(!a&&!b)return;unsigned long long in,out;if(!a||!b||!number(a,&in)||!number(b,&out)||in<3||out<3||in>INT_MAX||out>INT_MAX)_exit(125);
 if(write((int)out,stage,strlen(stage))!=(ssize_t)strlen(stage)||write((int)out,"\n",1)!=1){_exit(125);}
 struct pollfd f={(int)in,POLLIN,0};char c;if(poll(&f,1,500)!=1||read((int)in,&c,1)!=1||c!='G')_exit(125);
}
#else
static void hook(const char *stage){(void)stage;}
#endif
static int index_of(pid_t tid){for(size_t i=0;i<task_count;i++)if(tasks[i].tid==tid)return(int)i;return -1;}
static int inventory(pid_t group,pid_t tids[MAX_TASKS],size_t *count){
 char path[80];snprintf(path,sizeof(path),"/proc/%ld/task",(long)group);DIR *d=opendir(path);if(!d)return 0;*count=0;struct dirent *e;errno=0;
 while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;unsigned long long v;if(!number(e->d_name,&v)||v<=1||v>INT_MAX||*count>=MAX_TASKS){closedir(d);failure="task_inventory_limit_or_parse";return 0;}tids[(*count)++]=(pid_t)v;}
 int error=errno;closedir(d);if(error||!*count)return 0;for(size_t i=0;i<*count;i++)for(size_t j=i+1;j<*count;j++)if(tids[j]<tids[i]){pid_t a=tids[j];tids[j]=tids[i];tids[i]=a;}for(size_t i=1;i<*count;i++)if(tids[i-1]==tids[i])return 0;return 1;
}
static int add_task(pid_t tid,const struct plan *v,int exe,const struct stat *es){
 struct proc p;if(!process(tid,&p)){failure="task_disappeared_or_proc_invalid";return 0;}if(p.tgid!=(pid_t)v->pid){outside_observed=1;failure="observed_outside_group_relation";return 0;}if(task_count>=MAX_TASKS){failure="task_limit";return 0;}
 if(p.state=='Z'||p.state=='X'||p.pending||p.shared||p.threads>MAX_TASKS){failure="task_terminal_pending_or_count_limit";return 0;}
 for(int i=0;i<4;i++)if(p.uid[i]!=v->uid||p.gid[i]!=v->gid){failure="task_credentials_differ";return 0;}
 int tracer=p.tracer;unsigned long long start=p.start;int initial=tracer==getpid();if(tracer!=0&&!initial){failure="foreign_tracer";return 0;}
 if(!task_identity(tid,start,v,tracer,exe,es,NULL,0)){failure="task_identity_differs";return 0;}
 if(!initial){if(p.state=='T'||p.state=='t'){failure="original_group_or_trace_stop";return 0;}if(ptrace(PTRACE_SEIZE,tid,0,(void*)(uintptr_t)OPTIONS)){failure="seize_refused_no_policy_change";return 0;}}
 struct held *t=&tasks[task_count++];memset(t,0,sizeof(*t));t->tid=tid;t->start=start;t->initial=initial;
 hook(tid==(pid_t)v->pid?"leader-seized":"thread-seized");
 if(!task_identity(tid,start,v,getpid(),exe,es,NULL,0)){failure="post_seize_identity_differs";return 0;}
 if(ptrace(PTRACE_INTERRUPT,tid,0,0)){failure="interrupt_refused";return 0;}return 1;
}
static int inspect_stop(struct held *t,int verify_child,const struct plan *v,int exe,const struct stat *es,int pending_allowed){
 struct proc p;siginfo_t si;memset(&si,0,sizeof(si));if(!t->stopped||!task_identity(t->tid,t->start,v,getpid(),exe,es,&p,pending_allowed)||p.state!='t'){failure="held_task_identity_or_state_changed";return 0;}
 if(ptrace(PTRACE_GETSIGINFO,t->tid,0,&si)){failure="held_kernel_stop_lost";return 0;}
 if(si.si_signo!=SIGTRAP||si.si_code!=(int)(SIGTRAP|((unsigned)t->event<<8))||t->signal!=SIGTRAP||(t->event!=PTRACE_EVENT_STOP&&t->event!=PTRACE_EVENT_CLONE)){failure="retained_nonsignal_event_changed";return 0;}
 if(t->event==PTRACE_EVENT_CLONE){unsigned long child=0;if(ptrace(PTRACE_GETEVENTMSG,t->tid,0,&child)||child!=t->child){failure="clone_event_binding_changed";return 0;}if(verify_child){int i=index_of((pid_t)child);if(child>INT_MAX||i<0||!task_identity(tasks[i].tid,tasks[i].start,v,getpid(),exe,es,NULL,0)){failure="clone_child_not_bound_same_group";return 0;}}}
 return 1;
}
/* Linux3.10 waitid rejects __WALL/__WCLONE; do not consume ANY event.
 * GETSIGINFO itself runs ptrace_check_attach + wait_task_inactive in the kernel.
 * An unexpected delivery's exit_code is untouched for tracer-exit unlink. */
static int poll_stops(const struct plan *v,int exe,const struct stat *es){
 for(size_t i=0;i<task_count;i++){
  struct held *t=&tasks[i];
  if(t->stopped){if(!inspect_stop(t,0,v,exe,es,0))return 0;continue;}
  struct proc p;if(!task_identity(t->tid,t->start,v,getpid(),exe,es,&p,0)){failure="pending_task_identity_or_relation_lost";return 0;}
  siginfo_t si;memset(&si,0,sizeof(si));
  if(ptrace(PTRACE_GETSIGINFO,t->tid,0,&si)){
   int error=errno;
   if(error==ESRCH){
    /* ESRCH is not an accepted stop. It is pending ONLY while the original
     * kernel relation and all captured identity/pending fields still match. */
    if(!task_identity(t->tid,t->start,v,getpid(),exe,es,NULL,0)){failure="pending_kernel_relation_lost";return 0;}
    continue;
   }
   failure="kernel_stop_query_refused";return 0;
  }
  t->signal=si.si_signo;t->event=(int)((unsigned)si.si_code>>8);
  if(t->event==PTRACE_EVENT_EXEC){failure="exec_during_acquisition";return 0;}
  if(t->event==PTRACE_EVENT_EXIT){failure="exit_during_acquisition";return 0;}
  if(t->signal!=SIGTRAP||si.si_code!=(int)(SIGTRAP|((unsigned)t->event<<8))||(t->event!=PTRACE_EVENT_STOP&&t->event!=PTRACE_EVENT_CLONE)){failure="unexpected_signal_or_group_stop";return 0;}
  if(++event_count>MAX_EVENTS){failure="event_limit";return 0;}t->stopped=1;
  if(t->event==PTRACE_EVENT_CLONE){
   if(ptrace(PTRACE_GETEVENTMSG,t->tid,0,&t->child)||t->child<=1||t->child>INT_MAX){failure="clone_message_invalid";return 0;}
   if(index_of((pid_t)t->child)<0&&!add_task((pid_t)t->child,v,exe,es))return 0;
  }
  hook("after-stop-query");
  if(!inspect_stop(t,0,v,exe,es,0))return 0;
 }
 return 1;
}
static int closure(const struct plan *v,int exe,const struct stat *es){
 pid_t ids[MAX_TASKS];size_t n=0;struct proc leader;
 if(!inventory((pid_t)v->pid,ids,&n)||n!=task_count){failure="closed_inventory_differs";return 0;}
 for(size_t k=0;k<n;k++)if(index_of(ids[k])<0){failure="closed_inventory_unknown_tid";return 0;}
 /* This count/pending sample is read under Linux's sighand lock. It precedes
  * the complete kernel stop/leader verification below, not two timed samples. */
 if(!process((pid_t)v->pid,&leader)||leader.threads!=(int)n||leader.pending||leader.shared||leader.start!=v->start||leader.tgid!=(pid_t)v->pid){failure="closed_threads_count_or_leader_differs";return 0;}
 for(size_t i=0;i<task_count;i++)if(!inspect_stop(&tasks[i],1,v,exe,es,0))return 0;
 if(!within(whole_deadline)){failure=cancelled?"operator_cancel":"whole_elapsed_budget";return 0;}
 return 1;
}
static int acquire(const struct plan *v,int exe,const struct stat *es){
 long long deadline=now_ms()+ACQUIRE_MS;if(!arm_budget(ACQUIRE_MS,1)){failure="acquisition_timer_refused";return 0;}
 while(within(deadline)){
  pid_t ids[MAX_TASKS];size_t n=0;if(!inventory((pid_t)v->pid,ids,&n)){failure="acquisition_inventory_invalid";return 0;}
  for(size_t k=0;k<n;k++)if(index_of(ids[k])<0&&!add_task(ids[k],v,exe,es))return 0;
  if(!poll_stops(v,exe,es))return 0;
  int all=task_count>0;for(size_t i=0;i<task_count;i++)if(!tasks[i].stopped)all=0;
  if(all){return closure(v,exe,es);}
  usleep(1000);
 }
 failure=cancelled?"operator_cancel":"acquisition_elapsed_budget";return 0;
}
static void detach_known(const struct plan *v,int exe,const struct stat *es){
 long long end=now_ms()+CLEANUP_MS;if(!arm_budget(CLEANUP_MS,3)){cleanup_partial=1;return;}
 for(size_t i=0;i<task_count;i++){
  if(now_ms()>end){cleanup_partial=1;break;}
  struct held *t=&tasks[i];const char *saved=failure;
  if(inspect_stop(t,0,v,exe,es,1)&&!ptrace(PTRACE_DETACH,t->tid,0,0))detach_count++;else cleanup_partial=1;failure=saved;
 }
 /* Never enumerate/control outside tracees. exit_ptrace() unlinks even an
  * inherited child whose initial event we never observed. No EXITKILL option.
  * DETACH0 is never used for an unknown signal-delivery/group/EXIT stop. */
}
int main(int argc,char **argv){
 int planfd=-1,exe=-1,copy=-1,state=-1,snapshot=-1,lock=-1,success=0;struct plan v={0};struct stat ps={0},es={0},bs={0},ss={0},sbs={0},ls={0},home={0},receipt_dir={0},native_dir={0};char parent[PATH_MAX]={0},binary[PATH_MAX]={0},snap[PATH_MAX]={0},lockpath[PATH_MAX]={0},native[PATH_MAX]={0},procpath[80]={0};
 long long started=now_ms();if(started<0)_exit(125);whole_deadline=started+WHOLE_MS;private_deadline=whole_deadline;
 /* Establish a deliverable watchdog BEFORE any refusal/output or attachment.
  * Exec may inherit SIG_IGN or a blocked mask; neither may defeat cleanup. */
 struct sigaction watchdog={0};watchdog.sa_handler=hard_timeout;sigemptyset(&watchdog.sa_mask);
 sigset_t alarm_mask;sigemptyset(&alarm_mask);sigaddset(&alarm_mask,SIGALRM);
 if(sigaction(SIGALRM,&watchdog,NULL)||!arm_budget(WHOLE_MS,0)||sigprocmask(SIG_UNBLOCK,&alarm_mask,NULL))_exit(125);
 NEED(geteuid()==0,"root_required");NEED(argc==3&&(!strcmp(argv[1],"--probe")||!strcmp(argv[1],"--terminate")),"explicit_mode_and_private_schema2_request_required");NEED(strlen(argv[2])<PATH_MAX&&namespace_ok(argv[2]),"thread_stop_namespace_required");
 struct sigaction d={0};d.sa_handler=SIG_DFL;sigemptyset(&d.sa_mask);NEED(!sigaction(SIGCHLD,&d,NULL),"sigchld_default_required");struct sigaction sa={0};sa.sa_handler=cancel;sigemptyset(&sa.sa_mask);NEED(!sigaction(SIGINT,&sa,NULL)&&!sigaction(SIGTERM,&sa,NULL)&&!sigaction(SIGHUP,&sa,NULL),"cancel_handler_failed");sigset_t cancel_mask;sigemptyset(&cancel_mask);sigaddset(&cancel_mask,SIGINT);sigaddset(&cancel_mask,SIGTERM);sigaddset(&cancel_mask,SIGHUP);NEED(!sigprocmask(SIG_UNBLOCK,&cancel_mask,NULL),"cancel_mask_failed");
 planfd=private_file(argv[2],0600,8192,&ps);NEED(planfd>=0&&parse(planfd,&v),"private_schema2_request_invalid");strcpy(parent,argv[2]);char *slash=strrchr(parent,'/');NEED(slash&&!strcmp(slash,"/stop.request"),"request_basename_differs");*slash=0;
 NEED(!lstat(parent,&home)&&S_ISDIR(home.st_mode)&&home.st_uid==0&&home.st_gid==0&&(home.st_mode&07777)==0700,"private_receipt_directory_differs");receipt_dir=home;
 NEED(snprintf(binary,sizeof(binary),"%s/binary.before",parent)<PATH_MAX&&snprintf(snap,sizeof(snap),"%s/state.before",parent)<PATH_MAX,"snapshot_path_bound");copy=private_file(binary,0555,64*1024*1024,&bs);snapshot=private_file(snap,0600,1024*1024,&sbs);state=private_file(v.state,0600,1024*1024,&ss);NEED(copy>=0&&snapshot>=0&&state>=0,"custody_snapshot_invalid");
 strcpy(native,v.state);slash=strrchr(native,'/');NEED(slash&&!strcmp(slash,"/state.json"),"native_state_basename_differs");*slash=0;NEED(!lstat(native,&home)&&S_ISDIR(home.st_mode)&&home.st_uid==0&&home.st_gid==0&&(home.st_mode&07777)==0700,"native_home_differs");native_dir=home;
 NEED(snprintf(lockpath,sizeof(lockpath),"%s/state.lock",native)<PATH_MAX,"lock_path_bound");lock=private_file(lockpath,0600,0,&ls);NEED(lock>=0&&!flock(lock,LOCK_EX|LOCK_NB),"native_state_lock_unavailable");
 snprintf(procpath,sizeof(procpath),"/proc/%llu/exe",v.pid);exe=open(procpath,O_RDONLY|O_CLOEXEC);NEED(exe>=0&&!fstat(exe,&es)&&S_ISREG(es.st_mode)&&es.st_uid==0&&es.st_gid==0&&!(es.st_mode&0022)&&(unsigned long long)es.st_dev==v.exe_dev&&(unsigned long long)es.st_ino==v.exe_ino&&(unsigned long long)es.st_size==v.exe_size,"held_executable_differs");
 NEED(arm_budget(PRIVATE_MS,2),"private_comparison_timer_refused");private_deadline=now_ms()+PRIVATE_MS;struct proc leader;NEED(task_identity((pid_t)v.pid,v.start,&v,0,exe,&es,&leader,0)&&leader.state!='T'&&leader.state!='t'&&leader.threads<=MAX_TASKS&&compare_fds(exe,copy,64*1024*1024)&&compare_fds(state,snapshot,1024*1024),"original_identity_or_state_differs");hook("before-acquire");
 NEED(acquire(&v,exe,&es),failure);NEED(arm_budget(PRIVATE_MS,2),"private_comparison_timer_refused");hook("after-acquire");private_deadline=now_ms()+PRIVATE_MS;
 NEED(within(private_deadline)&&unchanged(planfd,argv[2],&ps)&&unchanged(copy,binary,&bs)&&unchanged(snapshot,snap,&sbs)&&unchanged(state,v.state,&ss)&&unchanged_lock(lock,lockpath,&ls)&&!lstat(parent,&home)&&same(&home,&receipt_dir)&&!lstat(native,&home)&&same(&home,&native_dir)&&compare_fds(exe,copy,64*1024*1024)&&compare_fds(state,snapshot,1024*1024)&&within(private_deadline),"private_custody_or_comparison_budget_changed");
 NEED(!cancelled,"operator_cancel");NEED((unsigned long long)time(NULL)>=v.checked_at&&(unsigned long long)time(NULL)<=v.valid_until,"private_plan_expired");NEED(arm_budget(WHOLE_MS,4),"commit_timer_refused");hook("before-final");NEED(closure(&v,exe,&es),failure);final_accepted=1;
 /* FINAL ACCEPTANCE: no wait/reap/CONT/LISTEN/detach/attach before ONE queue.
  * Kernel-held group closure excludes the unsafe nonleader-exec replacement.
  * A fatal original exit still belongs to our unreaped ptrace relation. */
 hook("after-final");if(!strcmp(argv[1],"--terminate")){NEED(kill((pid_t)v.pid,SIGTERM)==0,"queue_failed_no_fallback");queued=1;}hook("after-queue");detach_known(&v,exe,&es);if(cleanup_partial)failure="known_cleanup_partial_after_decision";success=!cleanup_partial;goto finished;
refused:
 /* No blind DETACH0 on refusal. Ordinary tracer exit preserves unexpected
  * delivery/group-stop state and unlinks unknown inherited relations. */
 success=0;if(!arm_budget(CLEANUP_MS,3))_exit(124);
finished:
 /* Keep the cleanup/whole watchdog armed through stdio flush and actual exit. */
 printf("{\"schema_version\":2,\"status\":\"%s\",\"reason\":\"%s\",\"target_group_closed\":%s,\"retained_task_count\":%zu,\"acquisition_event_count\":%u,\"sigterm_queued\":%s,\"single_positive_tgid_queue\":%s,\"outside_relationship_inventory_exhaustive\":false,\"observed_outside_relation_caused_refusal\":%s,\"explicit_outside_signal_sent\":false,\"known_nonsignal_detach_count\":%d,\"cleanup_partial\":%s,\"remaining_cleanup_basis\":\"kernel-tracer-exit-without-exitkill\",\"event_consumption_performed\":false,\"production_wait_syscalls\":false,\"pidfd_equivalence_claimed\":false,\"native_load_executed_by_helper\":false}\n",queued?(success?"termination-requested":"termination-requested-partial-cleanup"):(success?"probe-detached":"refused"),success?"none":failure,final_accepted?"true":"false",task_count,event_count,queued?"true":"false",queued?"true":"false",outside_observed?"true":"false",detach_count,cleanup_partial?"true":"false");
 int fds[]={planfd,exe,copy,state,snapshot,lock};for(int i=0;i<6;i++)if(fds[i]>=0)close(fds[i]);return success?0:1;
}
