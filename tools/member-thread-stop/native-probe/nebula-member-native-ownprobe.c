/* SOURCE ONLY. Native-host OWN inert-child acceptance harness, not a migrator.
 * No foreign PID input, ptrace implementation, native profile, network or pidfd.
 * Do not execute/stage until Root reviews and explicitly authorizes this packet.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#define CAPTURE_LIMIT 8192
#define CASE_COUNT 5
struct owned { pid_t pid;
 unsigned long long start;
 int reaped,status;
 };
struct proc { unsigned long long start;
 int tracer;
 char state;
 };
static volatile sig_atomic_t cancelled;
static int target_input=-1,target_events=-1;
static long long now_ms(void){struct timespec t;
if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void cancel(int n){(void)n;
cancelled=1;
}
static int nb(int fd){int f=fcntl(fd,F_GETFL);
return f>=0&&fcntl(fd,F_SETFL,f|O_NONBLOCK)==0;
}
static int path2(char out[PATH_MAX],const char *a,const char *b){int n=snprintf(out,PATH_MAX,"%s/%s",a,b);
return n>0&&n<PATH_MAX;
}
static int safe_path(const char *path){
 char real[PATH_MAX],copy[PATH_MAX];
struct stat s;
if(!realpath(path,real)||strcmp(real,path)||strlen(path)>=sizeof(copy))return 0;
strcpy(copy,path);
 if(lstat("/",&s)||!S_ISDIR(s.st_mode)||s.st_uid||(s.st_mode&0022))return 0;
 for(char *p=copy+1;;p++)if(*p=='/'||!*p){char c=*p;
*p=0;
if(lstat(copy,&s)||s.st_uid||(s.st_mode&0022)||S_ISLNK(s.st_mode))return 0;
*p=c;
if(!c)break;
}
 return 1;
}
static int private_dir(const char *p){struct stat s;
return safe_path(p)&&!lstat(p,&s)&&S_ISDIR(s.st_mode)&&s.st_uid==0&&s.st_gid==0&&(s.st_mode&07777)==0700;
}
static int regular(const char *p,mode_t mode,struct stat *out){
 if(!safe_path(p))return -1;
int fd=open(p,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
struct stat s,b;
 if(fd<0)return -1;
if(fstat(fd,&s)||lstat(p,&b)||s.st_dev!=b.st_dev||s.st_ino!=b.st_ino||!S_ISREG(s.st_mode)||s.st_uid||s.st_gid||s.st_nlink!=1||(s.st_mode&07777)!=mode){close(fd);
return -1;
}if(out)*out=s;
return fd;
}
static int new_file(const char *p,const void *raw,size_t size,mode_t mode){
 int fd=open(p,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode);
if(fd<0)return 0;
size_t off=0;
int ok=1;
 while(off<size){ssize_t n=write(fd,(const char*)raw+off,size-off);
if(n<0&&errno==EINTR){if(cancelled){ok=0;
break;
}continue;
}if(n<=0){ok=0;
break;
}off+=(size_t)n;
}
 if(fchmod(fd,mode)||fsync(fd))ok=0;
if(close(fd))ok=0;
return ok;
}
static int copy_held(int fd,const char *to){
 struct stat s;
if(fstat(fd,&s)||s.st_size<=0||s.st_size>1024*1024)return 0;
int out=open(to,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0555);
if(out<0)return 0;
off_t off=0;
char b[8192];
int ok=1;
 while(off<s.st_size){size_t n=(size_t)(s.st_size-off);
if(n>sizeof(b))n=sizeof(b);
ssize_t r=pread(fd,b,n,off);
if(r!=(ssize_t)n){ok=0;
break;
}size_t w=0;
while(w<n){ssize_t x=write(out,b+w,n-w);
if(x<0&&errno==EINTR)continue;
if(x<=0){ok=0;
break;
}w+=(size_t)x;
}if(!ok)break;
off+=(off_t)n;
}
 if(fchmod(out,0555)||fsync(out))ok=0;
close(out);
return ok;
}
static int proc(pid_t p,struct proc *out){
 memset(out,0,sizeof(*out));
char path[80],b[8192],*q,*save,*t;
snprintf(path,sizeof(path),"/proc/%ld/stat",(long)p);
FILE *f=fopen(path,"re");
if(!f)return 0;
size_t n=fread(b,1,sizeof(b)-1,f);
int bad=ferror(f)||!feof(f);
fclose(f);
if(bad||!n)return 0;
b[n]=0;
q=strrchr(b,')');
if(!q||q[1]!=' ')return 0;
q+=2;
int got=0;
 for(int k=3;(t=strtok_r(k==3?q:NULL," \n",&save));k++){if(k==3){if(t[1])return 0;
out->state=t[0];
}if(k==22){char *e;
errno=0;
out->start=strtoull(t,&e,10);
if(errno||*e||!out->start)return 0;
got=1;
break;
}}
 if(!got)return 0;
snprintf(path,sizeof(path),"/proc/%ld/status",(long)p);
f=fopen(path,"re");
if(!f)return 0;
got=0;
 while(fgets(b,sizeof(b),f))if(!strncmp(b,"TracerPid:",10)){char extra;
int v;
if(sscanf(b,"TracerPid: %d %c",&v,&extra)!=1||v<0){fclose(f);
return 0;
}out->tracer=v;
got=1;
}
 bad=ferror(f);
fclose(f);
return got&&!bad;
}
static int bind_child(struct owned *p,pid_t pid){
 memset(p,0,sizeof(*p));
p->pid=pid;
struct proc a;
long long until=now_ms()+300;
while(now_ms()<until){if(proc(pid,&a)){p->start=a.start;
return 1;
}usleep(1000);
}return 0;
}
/* Only ordinary fork/SIGCHLD children. No __WALL/__WCLONE on upstream3.10.
 * No waitpid before terminal confirmation; never reap while future signals remain. */
static int terminal(struct owned *p,siginfo_t *result){
 if(p->pid<=1||p->reaped)return -1;
siginfo_t s;
memset(&s,0,sizeof(s));
 if(waitid(P_PID,(id_t)p->pid,&s,WEXITED|WNOWAIT|WNOHANG)){if(errno==EINTR)return 0;
return -1;
}
 if(!s.si_pid)return 0;
if(s.si_pid!=p->pid||(s.si_code!=CLD_EXITED&&s.si_code!=CLD_KILLED&&s.si_code!=CLD_DUMPED))return -1;
if(result)*result=s;
return 1;
}
static int signal_owned(struct owned *p,int sig){
 if(p->pid<=1||p->reaped)return 0;
int t=terminal(p,NULL);
if(t<0)return 0;
if(t)return 1;
struct proc a;
if(!proc(p->pid,&a)||a.start!=p->start)return 0;
return kill(p->pid,sig)==0||errno==ESRCH;
}
static int reap_terminal(struct owned *p){
 if(terminal(p,NULL)!=1)return 0;
pid_t r;
do{r=waitpid(p->pid,&p->status,WNOHANG);
}while(r<0&&errno==EINTR);
if(r!=p->pid)return 0;
p->reaped=1;
return 1;
}
static int finish_owned(struct owned *p,int force){
 if(p->pid<=1||p->reaped)return 1;
int t=terminal(p,NULL);
if(t<0)return 0;
if(!t&&force&&!signal_owned(p,SIGKILL))return 0;
long long until=now_ms()+2000;
 while(now_ms()<until){t=terminal(p,NULL);
if(t<0)return 0;
if(t==1)return reap_terminal(p);
usleep(10000);
}return 0;
}
static void target_usr(int n){(void)n;
char c='U';
ssize_t x=write(target_events,&c,1);
(void)x;
}
static void *target_worker(void *unused){(void)unused;
char c;
for(;;){ssize_t n=read(target_input,&c,1);
if(n<0&&errno==EINTR)continue;
if(n==1&&c=='Q')_exit(0);
if(n<=0)_exit(110);
}return NULL;
}
static void run_target(int input,int events){
 target_input=input;
target_events=events;
struct sigaction a={0};
sigemptyset(&a.sa_mask);
a.sa_handler=SIG_DFL;
 if(sigaction(SIGTERM,&a,NULL)||sigaction(SIGALRM,&a,NULL)||sigaction(SIGINT,&a,NULL)||sigaction(SIGHUP,&a,NULL))_exit(111);
 sigset_t s;
sigemptyset(&s);
sigaddset(&s,SIGALRM);
sigaddset(&s,SIGTERM);
sigaddset(&s,SIGUSR1);
if(sigprocmask(SIG_UNBLOCK,&s,NULL))_exit(112);
alarm(20);
a.sa_handler=target_usr;
if(sigaction(SIGUSR1,&a,NULL))_exit(113);
 pthread_attr_t attr;
if(pthread_attr_init(&attr)||pthread_attr_setstacksize(&attr,65536))_exit(114);
pthread_t thread;
if(pthread_create(&thread,&attr,target_worker,NULL))_exit(115);
pthread_attr_destroy(&attr);
char c='R';
if(write(events,&c,1)!=1)_exit(116);
for(;;)pause();
}
static int exact_case_state(struct owned *target,char desired){struct proc p;
return proc(target->pid,&p)&&p.start==target->start&&p.tracer==0&&(desired?p.state==desired:(p.state!='T'&&p.state!='t'&&p.state!='Z'&&p.state!='X'));
}
static int contains_once(const char *s,const char *token){const char *p=strstr(s,token);
return p&&!strstr(p+strlen(token),token);
}
struct case_result {int passed,policy_blocked,cleanup_complete,helper_code,target_status,usr_count,target_pid,helper_pid,target_reaped,helper_reaped;
char scratch[PATH_MAX];
};
static int run_case(int which,int helper_fd,int self_fd,const char *capture,struct case_result *result){
 memset(result,0,sizeof(*result));
struct owned target={0},helper={0};
int cmd[2]={-1,-1},events[2]={-1,-1},go[2]={-1,-1},notice[2]={-1,-1},out[2]={-1,-1},err[2]={-1,-1};
char scratch[]="/run/nebula-member-thread-test-native-XXXXXX";
char op[PATH_MAX],home[PATH_MAX],p[PATH_MAX],request[PATH_MAX],stdout_path[PATH_MAX],stderr_path[PATH_MAX];
int ready=0,success=0;
size_t outn=0,errn=0,noticen=0;
char output[CAPTURE_LIMIT+1]={0},errors[CAPTURE_LIMIT+1]={0},notices[1024]={0};
int stuffed=which>=4;
size_t prefilled=0;
long long deadline=now_ms()+11000;
 if(!mkdtemp(scratch)||chmod(scratch,0700)||!private_dir(scratch))goto done;
strcpy(result->scratch,scratch);
 if(!path2(home,scratch,"native-home")||mkdir(home,0700)||!path2(p,home,"state.json")||!new_file(p,"{\"own_inert_fixture_only\":true,\"native_load_performed\":false}\n",sizeof("{\"own_inert_fixture_only\":true,\"native_load_performed\":false}\n")-1,0600))goto done;
 char state_path[PATH_MAX];
strcpy(state_path,p);
if(!path2(p,home,"state.lock")||!new_file(p,"",0,0600))goto done;
 char opname[40];
if(snprintf(opname,sizeof(opname),"thread-stop-%016x",which+1)<0||!path2(op,scratch,opname)||mkdir(op,0700))goto done;
 if(!path2(p,op,"binary.before")||!copy_held(self_fd,p)||!path2(p,op,"state.before"))goto done;
 static const char state[]="{\"own_inert_fixture_only\":true,\"native_load_performed\":false}\n";
if(!new_file(p,state,sizeof(state)-1,0600))goto done;
 if(pipe(cmd)||pipe(events))goto done;
pid_t expected_parent=getpid();
pid_t child=fork();
if(child<0)goto done;
if(!child){
if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=expected_parent)_exit(118);
close(cmd[1]);
close(events[0]);
run_target(cmd[0],events[1]);
_exit(117);
}if(!bind_child(&target,child))goto done;
close(cmd[0]);
cmd[0]=-1;
close(events[1]);
events[1]=-1;
if(!nb(cmd[1])||!nb(events[0]))goto done;
 while(now_ms()<deadline&&!cancelled){char c;
ssize_t n=read(events[0],&c,1);
if(n==1&&c=='R'){ready=1;
break;
}if(n<0&&errno!=EAGAIN&&errno!=EINTR)break;
usleep(1000);
}if(!ready)goto done;
 struct stat ex;
char procpath[80];
snprintf(procpath,sizeof(procpath),"/proc/%ld/exe",(long)target.pid);
if(stat(procpath,&ex))goto done;
 char text[PATH_MAX+512];
unsigned long long now=(unsigned long long)time(NULL);
int length=snprintf(text,sizeof(text),"schema=2\npid=%ld\nstart=%llu\nuid=0\ngid=0\nexe_dev=%llu\nexe_ino=%llu\nexe_size=%llu\nchecked_at=%llu\nvalid_until=%llu\nnative_load_preflight=1\nstate=%s\n",(long)target.pid,target.start,(unsigned long long)ex.st_dev,(unsigned long long)ex.st_ino,(unsigned long long)ex.st_size,now,now+120,state_path);
 if(length<=0||(size_t)length>=sizeof(text)||!path2(request,op,"stop.request")||!new_file(request,text,(size_t)length,0600))goto done;
 if(pipe(go)||pipe(notice)||pipe(out)||pipe(err))goto done;
 if(stuffed){if(!nb(out[1]))goto done;
char fill[4096];
memset(fill,'F',sizeof(fill));
for(;;){ssize_t n=write(out[1],fill,sizeof(fill));
if(n>0){prefilled+=(size_t)n;
continue;
}if(n<0&&errno==EAGAIN)break;
goto done;
}int flags=fcntl(out[1],F_GETFL);
if(flags<0||fcntl(out[1],F_SETFL,flags&~O_NONBLOCK))goto done;
}
 expected_parent=getpid();
child=fork();
if(child<0)goto done;
 if(!child){
if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=expected_parent)_exit(119);
  close(go[1]);
close(notice[0]);
close(out[0]);
close(err[0]);
close(events[0]);
close(cmd[1]);
  int dev=open("/dev/null",O_RDONLY);
if(dev<0||dup2(dev,0)<0||dup2(out[1],1)<0||dup2(err[1],2)<0)_exit(120);
  char in[64],writefd[64],homeenv[PATH_MAX+8];
snprintf(in,sizeof(in),"NEBULA_TEST_IN=%d",go[0]);
snprintf(writefd,sizeof(writefd),"NEBULA_TEST_OUT=%d",notice[1]);
snprintf(homeenv,sizeof(homeenv),"HOME=%s",scratch);
char *env[]={"PATH=/usr/bin:/bin","LC_ALL=C",homeenv,in,writefd,NULL};
char *args[]={"own-thread-stop-fixture",which==1?"--terminate":"--probe",request,NULL};
fexecve(helper_fd,args,env);
_exit(127);
 }
 if(!bind_child(&helper,child))goto done;
close(go[0]);
go[0]=-1;
close(notice[1]);
notice[1]=-1;
close(out[1]);
out[1]=-1;
close(err[1]);
err[1]=-1;
if(!nb(go[1])||!nb(notice[0])||!nb(out[0])||!nb(err[0]))goto done;
 while(now_ms()<deadline&&!cancelled){
  char b[1024];
ssize_t n=read(notice[0],b,sizeof(b));
  if(n>0){if(noticen+(size_t)n>=sizeof(notices))goto done;
memcpy(notices+noticen,b,(size_t)n);
noticen+=(size_t)n;
size_t start=0;
   for(size_t i=0;i<noticen;i++)if(notices[i]=='\n'){notices[i]=0;
const char *stage=notices+start;
    if(!strcmp(stage,"leader-seized")&&which==2){if(syscall(SYS_tgkill,target.pid,target.pid,SIGUSR1))goto done;
usleep(20000);
}
    if(!strcmp(stage,"leader-seized")&&which==3){if(!signal_owned(&target,SIGSTOP))goto done;
usleep(20000);
}
    if(write(go[1],"G",1)!=1&&errno!=EPIPE)goto done;
start=i+1;
   }
   if(start){memmove(notices,notices+start,noticen-start);
noticen-=start;
}
  }else if(n<0&&errno!=EAGAIN&&errno!=EINTR)goto done;
  if(!stuffed){n=read(out[0],output+outn,CAPTURE_LIMIT-outn);
if(n>0)outn+=(size_t)n;
else if(n<0&&errno!=EAGAIN&&errno!=EINTR)goto done;
if(outn==CAPTURE_LIMIT)goto done;
}
  n=read(err[0],errors+errn,CAPTURE_LIMIT-errn);
if(n>0)errn+=(size_t)n;
else if(n<0&&errno!=EAGAIN&&errno!=EINTR)goto done;
if(errn==CAPTURE_LIMIT)goto done;
  char markers[32];
n=read(events[0],markers,sizeof(markers));
if(n>0)for(ssize_t i=0;i<n;i++)if(markers[i]=='U')result->usr_count++;
  int t=terminal(&helper,NULL);
if(t<0)goto done;
if(t==1){if(!reap_terminal(&helper))goto done;
break;
}usleep(1000);
 }
 if(!helper.reaped)goto done;
 if(!stuffed){for(;;){ssize_t n=read(out[0],output+outn,CAPTURE_LIMIT-outn);
if(n>0)outn+=(size_t)n;
else break;
if(outn==CAPTURE_LIMIT)goto done;
}}
 else{char b[4096];
size_t total=0;
for(;;){ssize_t n=read(out[0],b,sizeof(b));
if(n>0){total+=(size_t)n;
if(total>prefilled+CAPTURE_LIMIT)goto done;
}else break;
}if(total!=prefilled)goto done;
}
 output[outn]=0;
errors[errn]=0;
result->helper_code=WIFEXITED(helper.status)?WEXITSTATUS(helper.status):128+WTERMSIG(helper.status);
 if(!path2(stdout_path,capture,"helper.stdout")||!path2(stderr_path,capture,"helper.stderr")||!new_file(stdout_path,output,outn,0600)||!new_file(stderr_path,errors,errn,0600))goto done;
 if(strstr(output,"\"reason\":\"seize_refused_no_policy_change\"")){result->policy_blocked=1;
goto done;
}
 if(which==1){
  if(result->helper_code!=0||!contains_once(output,"\"sigterm_queued\":true")||!contains_once(output,"\"status\":\"termination-requested\"")||!contains_once(output,"\"cleanup_partial\":false")||!contains_once(output,"\"single_positive_tgid_queue\":true"))goto done;
  if(!finish_owned(&target,0)||!WIFSIGNALED(target.status)||WTERMSIG(target.status)!=SIGTERM)goto done;
 }else{
  if(stuffed){if(result->helper_code!=124||outn)goto done;
}
  else if(which==2||which==3){if(!contains_once(output,"\"status\":\"refused\"")||!contains_once(output,"\"sigterm_queued\":false"))goto done;
}
  else if(result->helper_code||!contains_once(output,"\"status\":\"probe-detached\"")||!contains_once(output,"\"sigterm_queued\":false"))goto done;
  long long until=now_ms()+400;
while(now_ms()<until){char b[32];
ssize_t n=read(events[0],b,sizeof(b));
if(n>0)for(ssize_t i=0;i<n;i++)if(b[i]=='U')result->usr_count++;
if((which!=2||result->usr_count==1)&&exact_case_state(&target,which==3?'T':0))break;
usleep(1000);
}
  if(!exact_case_state(&target,which==3?'T':0)||(which==2&&result->usr_count!=1))goto done;
  if(which==3&&!signal_owned(&target,SIGCONT))goto done;
  if(write(cmd[1],"Q",1)!=1||!finish_owned(&target,0)||!WIFEXITED(target.status)||WEXITSTATUS(target.status))goto done;
 }
 if(which==2){
  char b[32];ssize_t n;
  while((n=read(events[0],b,sizeof(b)))>0){for(ssize_t i=0;i<n;i++)if(b[i]=='U')result->usr_count++;}
  if(result->usr_count!=1)goto done;
 }
 success=1;
done:
 /* Always unwind tracer FIRST. No async handler or competing waiter can reap
  * these original ordinary-fork children before their last numeric decision. */
 result->cleanup_complete=finish_owned(&helper,1)&&finish_owned(&target,1);
result->target_status=target.status;
result->target_pid=(int)target.pid;
result->helper_pid=(int)helper.pid;
result->target_reaped=target.reaped;
result->helper_reaped=helper.reaped;
result->passed=success&&result->cleanup_complete;
 int *fds[]={cmd,events,go,notice,out,err};
for(size_t i=0;i<sizeof(fds)/sizeof(fds[0]);i++)for(int j=0;j<2;j++)if(fds[i][j]>=0)close(fds[i][j]);
return result->passed;
}
static int prefix_hex(const char *p,const char *prefix,const char *suffix){size_t n=strlen(prefix);
if(strncmp(p,prefix,n)||strlen(p)!=n+16+strlen(suffix))return 0;
for(int i=0;i<16;i++)if(!((p[n+i]>='0'&&p[n+i]<='9')||(p[n+i]>='a'&&p[n+i]<='f')))return 0;
return !strcmp(p+n+16,suffix);
}
int main(int argc,char **argv){
 /* No inherited stdio writes. All output is a NEW root-private receipt. */
 umask(077);
if(geteuid()!=0||argc!=4||strcmp(argv[1],"--fixtures")||!prefix_hex(argv[2],"/root/nebula-member-native-probe-","/build")||!prefix_hex(argv[3],"/root/nebula-member-ownprobe-","")||!private_dir(argv[2]))return 64;
 struct sigaction a={0};
a.sa_handler=SIG_DFL;
sigemptyset(&a.sa_mask);
if(sigaction(SIGCHLD,&a,NULL))return 65;
a.sa_handler=SIG_IGN;
if(sigaction(SIGPIPE,&a,NULL))return 65;
a.sa_handler=cancel;
if(sigaction(SIGALRM,&a,NULL)||sigaction(SIGTERM,&a,NULL)||sigaction(SIGINT,&a,NULL)||sigaction(SIGHUP,&a,NULL))return 66;
 sigset_t mask;
sigemptyset(&mask);
sigaddset(&mask,SIGALRM);
sigaddset(&mask,SIGTERM);
sigaddset(&mask,SIGINT);
sigaddset(&mask,SIGHUP);
if(sigprocmask(SIG_UNBLOCK,&mask,NULL))return 67;
alarm(90);
struct rlimit core={0,0};
if(setrlimit(RLIMIT_CORE,&core))return 68;
 char fixture[PATH_MAX],selfpath[PATH_MAX],release[PATH_MAX],summary[PATH_MAX];
struct stat st;
int helper=-1,self=-1,rel=-1;
 if(!path2(fixture,argv[2],"thread-stop-fixture")||!path2(selfpath,argv[2],"thread-stop-ownprobe")||!path2(release,argv[2],"thread-stop-release"))return 69;
 helper=regular(fixture,0555,NULL);
self=regular(selfpath,0555,&st);
rel=regular(release,0555,NULL);
struct stat running;
if(helper<0||self<0||rel<0||stat("/proc/self/exe",&running)||st.st_dev!=running.st_dev||st.st_ino!=running.st_ino)return 70;
close(rel);
 if(mkdir(argv[3],0700)||!private_dir(argv[3]))return 71;
 int passed=0,blocked=0,cleanup=1;
for(int i=0;i<CASE_COUNT&&!cancelled;i++){
  char name[32],dir[PATH_MAX],result_path[PATH_MAX];
snprintf(name,sizeof(name),"case-%02d",i+1);
if(!path2(dir,argv[3],name)||mkdir(dir,0700))break;
struct case_result r;
run_case(i,helper,self,dir,&r);
cleanup=cleanup&&r.cleanup_complete;
blocked=r.policy_blocked;
char record[PATH_MAX+512];
int n=snprintf(record,sizeof(record),"{\"case\":%d,\"passed\":%s,\"policy_blocked\":%s,\"cleanup_complete\":%s,\"helper_code\":%d,\"usr1_handler_count\":%d,\"scratch\":\"%s\",\"fake_profile_only\":true,\"native_load_performed\":false,\"own_target_pid\":%d,\"own_helper_pid\":%d,\"target_reaped\":%s,\"helper_reaped\":%s}\n",i+1,r.passed?"true":"false",r.policy_blocked?"true":"false",r.cleanup_complete?"true":"false",r.helper_code,r.usr_count,r.scratch,r.target_pid,r.helper_pid,r.target_reaped?"true":"false",r.helper_reaped?"true":"false");
  if(n<=0||(size_t)n>=sizeof(record)||!path2(result_path,dir,"result.json")||!new_file(result_path,record,(size_t)n,0600))break;
if(r.passed)passed++;
else break;
 }
 char record[768];
int n=snprintf(record,sizeof(record),"{\"schema_version\":1,\"status\":\"%s\",\"cases_passed\":%d,\"cases_expected\":%d,\"all_owned_children_cleaned\":%s,\"cancelled\":%s,\"release_binary_executed\":false,\"real_native_data_used\":false,\"policy_relaxation_performed\":false,\"foreign_pid_input_supported\":false,\"no_pidfd_assumption\":true}\n",blocked?"blocked_existing_policy":(passed==CASE_COUNT&&cleanup?"passed":"refused"),passed,CASE_COUNT,cleanup?"true":"false",cancelled?"true":"false");
 if(n<=0||(size_t)n>=sizeof(record)||!path2(summary,argv[3],"summary.json")||!new_file(summary,record,(size_t)n,0600))return 72;
close(helper);
close(self);
return blocked?2:(passed==CASE_COUNT&&cleanup?0:1);
}
