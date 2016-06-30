## 目录

* [声明](#声明)
* [同步消息和异步消息](#同步消息和异步消息)
* [nanomsg简介](#nanomsg简介)
* [环境配置](#环境配置)
* [测试用例](#测试用例)
    * [x] PAIR - simple one-to-one communication  
    * [x] BUS - simple many-to-many communication  
    * [ ] REQREP - allows to build clusters of stateless services to process user requests  
	* [ ] PUBSUB - distributes messages to large sets of interested subscribers  
    * [ ] PIPELINE - aggregates messages from multiple sources and load balances them among many destinations  
    * [ ] SURVEY - allows to query state of multiple applications in a single go  
* [代码分析](#代码分析)
	* [x] nn.h - 对外暴露的接口
	* [x] transport.h - 通信层
	* [x] inproc.h - 通信层 -> 进程内(线程间)通信  url格式为inproc://test
	* [x] ipc.h - 通信层 -> 进程间通信  url格式为ipc:///tmp/test.ipc
	* [x] tcp.h - 通信层 -> tcp通信  url格式为tcp://*:5555
	* [x] ws.h - 通信层 -> websocket通信
	* [x] protocol.h - 协议层
	* [x] reqrep.h - 协议层 -> 请求/回复模式
	* [x] pubsub.h - 协议层 -> 扇入模式
	* [x] bus.h - 协议层 -> 总线模式
	* [x] pair.h - 协议层 -> 配对模式
	* [x] pipeline.h - 协议层 -> 扇出模式
	* [x] survey.h - 协议层 -> 调查模式
	* [x] utils   实用工具包，包含基本数据结构（list，queue，hash）互斥及原子操作（mutex，atomic）等
		* [x] alloc.c   alloc.h
		* [x] atomic.c   atomic.h
		* [x] attr.h
		* [x] chunk.c   chunk.h
		* [x] chunkref.c   chunkref.h
		* [x] clock.c   clock.h
		* [x] closefd.c   closefd.h
		* [x] condvar.c   condvar.h
		* [x] cont.h
		* [x] efd.h
		* [x] efd.c   efd.h
		* [x] efd_eventfd.h   efd_eventfd.inc
		* [x] efd_pipe.h   efd_pipe.inc
		* [x] efd_socketpair.h   efd_socketpair.inc
		* [x] efd_win.h   efd_win.inc
		* [x] err.c   err.h
		* [x] fast.h
		* [x] hash.c   hash.h
		* [x] list.c   list.h
		* [x] msg.c   msg.h
		* [x] mutex.c   mutex.h
		* [x] once.c   once.h
		* [x] queue.c   queue.h
		* [x] random.c   random.h
		* [x] sem.c   sem.h
		* [x] sleep.c   sleep.h
		* [x] stopwatch.c   stopwatch.h
		* [x] thread.c   thread.h
		* [x] thread_posix.h   thread_posix.inc
		* [x] thread_win.h   thread_win.inc
		* [x] win.h
		* [x] wire.c   wire.h
	* [ ] transports   通信层实现，包括（inproc:进程内通信；ipc:进程间通信；tcp：tcp通信）
		* [ ] inproc
			* [ ] binproc.c   binproc.h
			* [ ] cinproc.c   cinproc.h
			* [ ] inproc.c   inproc.h
			* [ ] ins.c   ins.h
			* [ ] msgqueue.c   msgqueue.h
			* [ ] sinproc.c   sinproc.h
		* [ ] ipc
			* [ ] aipc.c   aipc.h
			* [ ] bipc.c   bipc.h
			* [ ] cipc.c   cipc.h
			* [ ] ipc.c   ipc.h
			* [ ] sipc.c   sipc.h
		* [ ] tcp
			* [ ] atcp.c   atcp.h
			* [ ] btcp.c   btcp.h
			* [ ] ctcp.c   ctcp.h
			* [ ] stcp.c   stcp.h
			* [ ] tcp.c   tcp.h
		* [ ] utils
			* [ ] backoff.c   backoff.h
			* [ ] base64.c   base64.h
			* [ ] dns.c   dns.h
			* [ ] dns_getaddrinfo.h   dns_getaddrinfo.inc
			* [ ] dns_getaddrinfo_a.h   dns_getaddrinfo_a.inc
			* [ ] iface.c   iface.h
			* [ ] literal.c   literal.h
			* [ ] port.c   port.h
			* [ ] streamhdr.c   streamhdr.h
		* [ ] ws
			* [ ] aws.c   aws.h
			* [ ] bws.c   bws.h
			* [ ] cws.c   cws.h
			* [ ] sha1.c   sha1.h
			* [ ] sws.c   sws.h
			* [ ] ws.c   ws.h
			* [ ] ws_handshake.c   ws_handshake.h
	* [ ] protocols   协议层实现，包括（REQ/REP:请求/应答；PUB/SUB:发布订阅等.）
		* [ ] bus
			* [ ] bus.c   bus.h
			* [ ] xbus.c   xbus.h
		* [ ] pair
			* [ ] pair.c   pair.h
			* [ ] xpair.c   xpair.h
		* [ ] pipeline
			* [ ] pull.c   pull.h
			* [ ] push.c   push.h
			* [ ] xpull.c   xpull.h
			* [ ] xpush.c   xpush.h
		* [ ] pubsub
			* [ ] pub.c   pub.h
			* [ ] sub.c   sub.h
			* [ ] trie.c   trie.h
			* [ ] xpub.c   xpub.h
			* [ ] xsub.c   xsub.h
		* [ ] reprep
			* [ ] rep.c   rep.h
			* [ ] req.c   req.h
			* [ ] task.c   task.h
			* [ ] xrep.c   xrep.h
			* [ ] xreq.c   xreq.h
		* [ ] survey
			* [ ] respondent.c   respondent.h
			* [ ] surveyor.c   surveyor.h
			* [ ] xrespondent.c   xrespondent.h
			* [ ] xsurveyor.c   xsurveyor.h
		* [ ] utils
			* [ ] dist.c   dist.h
			* [ ] excl.c   excl.h
			* [ ] fq.c   fq.h
			* [ ] lb.c   lb.h
			* [ ] priolist.c   priolist.h
	* [ ] core   generic code，glue between the pieces
		* [ ] ep.c   ep.h
		* [ ] epbase.c
		* [ ] global.c   global.h
		* [ ] pipe.c
		* [ ] poll.c
		* [ ] sock.c   sock.h
		* [ ] sockbase.c
		* [ ] symbol.c
	* [ ] aio   线程池模拟的异步操作，带状态机的事件驱动
		* [ ] ctx.c   ctx.h
		* [ ] fsm.c   fsm.h
		* [ ] poller.c   poller.h
		* [ ] poller_epoll.h   poller_epoll.inc
		* [ ] poller_kqueue.h   poller_kqueue.inc
		* [ ] poller_poll.h   poller_poll.inc
		* [ ] pool.c   pool.h
		* [ ] timer.c   timer.h
		* [ ] timerset.c   timerset.h
		* [ ] usock.c   usock.h
		* [ ] usock_posix.h   usock_posix.inc
		* [ ] usock_win.h   usock_win.inc
		* [ ] worker.c   worker.h
		* [ ] worker_posix.h   worker_posix.inc
		* [ ] worker_win.h   worker_win.inc
	* [x] device
		* [x] device.c   device.h
* [其他文件](#其他文件)
	* [x] CMakeLists.txt
	* [x] pkgconfig.in
	* [x] README

声明
------
源码来自[github](https://github.com/nanomsg/nanomsg)  
部分分析参考[Tiger's Blog](http://absolutetiger.com/?p=225)  
简介参考[nanomsg.org](http://nanomsg.org/index.html)  
测试用例参考[Tim Dysinger's Blog](http://tim.dysinger.net/posts/2013-09-16-getting-started-with-nanomsg.html)  
同步消息和异步消息
------
消息通信的基本方式有两种：  
##### 同步（例如刚学linux c的时候用到的socket通信）  
两个通信应用服务之间必须要进行同步，两个服务之间必须都是正常运行的。发送程序和接收程序都必须一直处于运行状态，并且随时做好相互通信的准备。
发送程序首先向接收程序发起一个请求，称之为发送消息，发送程序紧接着就会堵塞当前自身的进程，不与其他应用进行任何的通信以及交互，等待接收程序的响应，待发送消息得到接收程序的返回消息之后会继续向下运行，进行下一步的业务处理。  
##### 异步（Java中JMS就是典型的异步消息处理机制，包括点对点和发布/订阅两种类型）  
两个通信应用之间可以不用同时在线等待，任何一方只需各自处理自己的业务，比如发送方发送消息以后不用登录接收方的响应，可以接着处理其他的任务。也就是说发送方和接收方都是相互独立存在的，发送方只管方，接收方只能接收，无须去等待对方的响应。  
nanomsg简介
------
nanomsg是zeromq作者Martin Sustrik用C重写的一套具有可扩展协议的一套通信框架，具体nanomsg与zeromq的不同与改进之处及为什么要用C重写在[这里](http://nanomsg.org/documentation-zeromq.html)有详细的描述，另外[Martin Sustrik的博客](http://250bpm.com/ )里面的每篇文章感觉都挺不错的，推荐关注订阅。

nanomsg是一个实现了几种“可扩展协议”的高性能通信库。可扩展协议的任务是定义多个应用系统如何通信，从而组成一个大的分布式系统。  
##### 当前版本nanomsg支持以下可扩展协议：  
* PAIR - simple one-to-one communication  
  配对模式：简单的一对一的通信
* BUS - simple many-to-many communication  
  总线模式：简单的多对多的通信；
* REQREP - allows to build clusters of stateless services to process user requests  
  请求/回复模式支持组建大规模的集群服务来处理用户请求
* PUBSUB - distributes messages to large sets of interested subscribers  
  扇入模式：支持从多个源聚合请求消息；  
* PIPELINE - aggregates messages from multiple sources and load balances them among many destinations
  扇出模式：支持分配到多个节点以支持负载均衡；  
* SURVEY - allows to query state of multiple applications in a single go  
  调查模式：允许在一个单一的请求里检查多个应用的状态；  

##### 可扩展协议是在网络通信协议之上实现的，当前版本nanomsg支持一下网络协议：  
* INPROC - transport within a process (between threads, modules etc.)
* IPC - transport between processes on a single machine 
* TCP - network transport via TCP 
* nanomsg用c实现，不依赖系统特性，所以支持多个操作系统。  

nanomsg对外暴露的接口api定义在nn.h中：
```c
NN_EXPORT int nn_socket (int domain, int protocol);
NN_EXPORT int nn_close (int s);
NN_EXPORT int nn_setsockopt (int s, int level, int option, 
                             const void *optval, size_t optvallen);
NN_EXPORT int nn_getsockopt (int s, int level, int option, 
                             void *optval, size_t *optvallen);
NN_EXPORT int nn_bind (int s, const char *addr);
NN_EXPORT int nn_connect (int s, const char *addr);
NN_EXPORT int nn_shutdown (int s, int how);
NN_EXPORT int nn_send (int s, const void *buf, size_t len, int flags);
NN_EXPORT int nn_recv (int s, void *buf, size_t len, int flags);
NN_EXPORT int nn_sendmsg (int s, const struct nn_msghdr *msghdr, int flags);
NN_EXPORT int nn_recvmsg (int s, struct nn_msghdr *msghdr, int flags);
NN_EXPORT int nn_device (int s1, int s2);
```  
熟悉socket接口api的人应该对这些接口不陌生，发送方和接收方必须同时在线等待  
所以一个简单的服务端应答程序大致是这样的：  
```c
char buf[10];
int s = nn_socket(AF_SP, NN_REP);
nn_bind(s, "tcp://*:5555");
nn_recv(s, buf, 10, 0);
nn_send(s, "World", 5, 0);
nn_close(s);
```
对应的客户端请求程序大致为：
```c
char buf[10];
int s = nn_socket(AF_SP, NN_REQ);
nn_connect(s, "tcp://localhost:5555");
nn_send(s, "Hello", 5, 0);
nn_recv(s, buf, 10, 0);
printf("Hello %sn", buf);
nn_close(s);
```
环境配置
------
下载[源码](https://github.com/nanomsg/nanomsg)  
然后[build](http://nanomsg.org/development.html)  
```
POSIX-compliant platforms

First, you have to have autotools installed. 
Once that is done following sequence of steps will build the project:
	$ git clone git@github.com:nanomsg/nanomsg.git
	$ cd nanomsg
	$ ./autogen.sh
	$ ./configure
	$ make
	$ make check
	$ sudo make install
To build a version with documentation (man pages and HTML reference) 
	included you will need asciidoc and xmlto tools installed.
To build it modify the ./configure step in following manner:
	$ ./configure --enable-doc
To build a version with debug info adjust the ./configure step as follows:
	$ ./configure --enable-debug
```
build需要先安装cmake  
#### Mac OS下  
brew install cmake  
src里面是头文件 移动到main.c目录下并改名为nanomsg  

##### xcode 
将libnanomsg.1.0.0-rc2.dylib添加到工程里面  
点击工程->targets->Build Phases->Link Binary With Libraries  
添加libnanomsg.1.0.0-rc2.dylib  

##### shell
将libnanomsg.1.0.0-rc2.dylib移到当前目录下
gcc -lnanomsg.1.0.0-rc2 -L. -o main main.c 
./main
  
#### Ubuntu下    
apt-get install cmake  
将 libnanomsg.so.5.0.0 移到/usr/local/lib目录下   
echo "/usr/local/lib" >> /etc/ld.so.conf  
ldconfig  
gcc  main.c -o main -lpthread -lnanomsg  
./main  

#### Cent OS服务器下  
yum install cmake
git失败
scp -r /Users/meteor/github/nanomsg-master root@115.159.36.21:/home/root
cp libnanomsg.so.5.0.0 /usr/local/lib
echo "/usr/local/lib" >> /etc/ld.so.conf
ldconfig
gcc  main.c -o main -lpthread -lnanomsg

#### 测试案例
##### 本地Mac OS与Ubuntu虚拟机的测试
本地ipc通信，pair模式，bus模式 
分别测试了Mac OS的ip地址和端口号tcp://10.189.99.235:5555  
Ubuntu虚拟机的ip地址和端口号tcp://192.168.250.135:5555  

##### 两台Cent OS服务器和本地Mac OS的测试
tcp://115.159.36.21:5555
tcp://115.29.39.184:5555
pair 成功
bus 失败，需要至少3个外网IP我只有两个啊orz

ws://115.159.36.21:5555 失败

##### Mac OS与Cent OS服务器的tcp通信 
tcp://115.159.36.21:5555
tcp://127.0.0.1:5555
tcp://localhost:5555

ws://115.159.36.21:5555
ws://127.0.0.1:5555
不成功

测试用例
------
PAIR - simple one-to-one communication
------
```c
	#include <stdio.h>
	#include <assert.h>
	#include <pthread.h>
	#include <stdlib.h>
	#include <string.h>
	#include "nanomsg/nn.h"
	#include "nanomsg/pair.h"
	#include "nanomsg/bus.h"
	#include "nanomsg/tcp.h"

void recv_msg(int sock)
{
    char *msg = NULL;
    printf("now you can receive messages...\n");
    while (1) {
        int result = nn_recv(sock, &msg, NN_MSG, 0);
        if (result > 0)
        {
            printf ("RECEIVED \"%s\"\n", msg);
            nn_freemsg (msg);
        }
    }
}

int main (const int argc, const char **argv)
{
    int sock;
    char transport[10];
    // choose transport : bus pair
    printf("please choose the transport...\n");
    while (1) {
        scanf("%s",transport);
        if (strcmp(transport, "pair")==0)
            sock = nn_socket (AF_SP, NN_PAIR);
        else if (strcmp(transport, "bus")==0)
            sock = nn_socket (AF_SP, NN_BUS);
        else {
            printf("no such transport\n");
            continue;
        }
        if(sock < 0) {
            printf("fail to create socket: %s\n", nn_strerror(errno));
            exit(errno);
        }
        break;
    }
    
    char bindOrConnect[10], url[100], next;
    int flag;
    // choose protocol
    // ipc://tmp/pair.ipc
    // tcp://115.29.39.184:5555
    printf("bind/connect protocol://url\n");
    while (1) {
        scanf("%s",bindOrConnect);
        scanf("%s",url);
        if (strcmp(bindOrConnect, "bind")==0)
            flag = nn_bind(sock, url);
        else if (strcmp(bindOrConnect, "connect")==0)
            flag = nn_connect(sock, url);
        else {
            printf("please select bind/connect\n");
            continue;
        }
        if ( flag >= 0 )
            printf("%s successful\n", bindOrConnect);
        else {
            printf("fail to %s to %s : %s\n", bindOrConnect, url, nn_strerror(errno));
            continue;
        }
        printf("do you want to do next?(y/n)\n");
        scanf("%c", &next);
        if ( next=='y') {
            break;
        }
        else {
            printf("continue\n");
        }
    }
    
    int to = 100; // timeout
    if(nn_setsockopt (sock, NN_SOL_SOCKET, NN_RCVTIMEO, &to, sizeof (to)) < 0) {
        printf("fail to set sorket opts: %sn", nn_strerror(errno));
        exit(errno);
    }
    
    // sub thread: receive message
    pthread_t thread;
    pthread_create(&thread, NULL, (void *)(&recv_msg), (void *)sock);
    
    // main thread: send message
    char msg[1024];
    printf("now you can send messages...\n");
    while(1) {
        scanf("%s", msg);
        if (strcmp(msg, "q")==0)
            break;
        printf ("SENDING \"%s\"\n", msg);
        size_t sz_n = strlen (msg) + 1;
        nn_send(sock, msg, sz_n, 0);
    }
    printf("exit\n");
    nn_shutdown(sock, 0);
    return 0;
}
```

代码分析
------ 
nn.h  
------
对外的基础头文件，主要包括供外部使用的接口定义，以及一些常量的定义
```
Handle DSO symbol visibility.  
	若 NN_EXPORT 未定义，则根据系统和库是否已加载分别定义为  
	__declspec(dllexport)  __declspec(dllimport)  extern
ABI versioning support.   
	定义当前接口版本  上一个接口版本  还有多少个接口版本仍然被支持
Errors.
	定义标准的错误信息，包括POSIX系统标准错误信息，nanomsg错误信息，error_t至少32位
	NN_EXPORT int nn_errno (void); //  检索errno，不是很懂什么意思
	NN_EXPORT const char *nn_strerror (int errnum); // 将 errnum 转化为字符串
Symbols.
	NN_EXPORT const char *nn_symbol (int i, int *value); // 根据 i 返回标志名称和它的值
	Constants that are returned in `ns` member of nn_symbol_properties
		定义 NN_NS 系列的标志
	Constants that are returned in `type` member of nn_symbol_properties
		定义 NN_TYPE 系列的标志
	Constants that are returned in the `unit` member of nn_symbol_properties
		定义 NN_UNIT 系列的标志
	struct nn_symbol_properties {
	    int value;  // The constant value
	    const char* name; // The constant name
	    int ns; // The constant namespace, or zero for namespaces themselves
	    int type; // The option type for socket option constants
	    int unit; // The unit for the option value for socket option constants
	};
	NN_EXPORT int nn_symbol_info (int i, struct nn_symbol_properties *buf, int buflen);
		定义 nn_symbol_properties 结构数组，如果 i 超过下标，则返回 0 ，否则返回长度
Helper function for shutting down multi-threaded applications.
	NN_EXPORT void nn_term (void);
		在多线程应用 shut down 的时候用到的一个函数
Zero-copy support.
	#define NN_MSG ((size_t) -1) // 定义 NN_MSG 长度
	NN_EXPORT void *nn_allocmsg (size_t size, int type); // 分配空间
	NN_EXPORT void *nn_reallocmsg (void *msg, size_t size); // 重新分配空间
	NN_EXPORT int nn_freemsg (void *msg); // 回收空间
Socket definition.
	struct nn_iovec {
	    void *iov_base;
	    size_t iov_len;
	};
	struct nn_msghdr {
	    struct nn_iovec *msg_iov;
	    int msg_iovlen;
	    void *msg_control;
	    size_t msg_controllen;
	};
	struct nn_cmsghdr {
	    size_t cmsg_len;
	    int cmsg_level;
	    int cmsg_type;
	};
Internal stuff. Not to be used directly. 内部使用的东西
	NN_EXPORT  struct nn_cmsghdr *nn_cmsg_nxthdr_ (
	    const struct nn_msghdr *mhdr,
	    const struct nn_cmsghdr *cmsg);
	#define NN_CMSG_ALIGN_(len) \
	    (((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1))
POSIX-defined msghdr manipulation.
	#define NN_CMSG_FIRSTHDR(mhdr) \
	    nn_cmsg_nxthdr_ ((struct nn_msghdr*) (mhdr), NULL)
	#define NN_CMSG_NXTHDR(mhdr, cmsg) \
	    nn_cmsg_nxthdr_ ((struct nn_msghdr*) (mhdr), (struct nn_cmsghdr*) (cmsg))
	#define NN_CMSG_DATA(cmsg) \
	    ((unsigned char*) (((struct nn_cmsghdr*) (cmsg)) + 1))
Extensions to POSIX defined by RFC 3542. // 不懂
	#define NN_CMSG_SPACE(len) \
	    (NN_CMSG_ALIGN_ (len) + NN_CMSG_ALIGN_ (sizeof (struct nn_cmsghdr)))
	#define NN_CMSG_LEN(len) \
	    (NN_CMSG_ALIGN_ (sizeof (struct nn_cmsghdr)) + (len))
SP address families.
Max size of an SP address.
Socket option levels: Negative numbers are reserved for transports,
    positive for socket types.
Generic socket options (NN_SOL_SOCKET level).
Send/recv options.
Ancillary data. // 辅助数据
// 供外部使用的接口
	NN_EXPORT int nn_socket (int domain, int protocol);
	NN_EXPORT int nn_close (int s);
	NN_EXPORT int nn_setsockopt (int s, int level, int option, const void *optval,
	    size_t optvallen);
	NN_EXPORT int nn_getsockopt (int s, int level, int option, void *optval,
	    size_t *optvallen);
	NN_EXPORT int nn_bind (int s, const char *addr);
	NN_EXPORT int nn_connect (int s, const char *addr);
	NN_EXPORT int nn_shutdown (int s, int how);
	NN_EXPORT int nn_send (int s, const void *buf, size_t len, int flags);
	NN_EXPORT int nn_recv (int s, void *buf, size_t len, int flags);
	NN_EXPORT int nn_sendmsg (int s, const struct nn_msghdr *msghdr, int flags);
	NN_EXPORT int nn_recvmsg (int s, struct nn_msghdr *msghdr, int flags);
Socket mutliplexing support. // 多路传输支持
	#define NN_POLLIN 1
	#define NN_POLLOUT 2
	struct nn_pollfd {
	    int fd;
	    short events;
	    short revents;
	};
	NN_EXPORT int nn_poll (struct nn_pollfd *fds, int nfds, int timeout);
Built-in support for devices. // 对 devices 的内置支持
	NN_EXPORT int nn_device (int s1, int s2);
Statistics. // 统计数字
	Transport statistics
	The socket-internal statistics
	Protocol statistics
	NN_EXPORT uint64_t nn_get_statistic (int s, int stat);
```

transport.h  
------
This is the API between the nanomsg core and individual transports.  
通信层定义，目的应该是想暴露给用户以实现可扩展，但目前还包含utils下头文件  
```
struct nn_sock;
struct nn_cp;
Container for transport-specific socket options. // 针对具体传输方式的socker容器
	struct nn_optset;
	struct nn_optset_vfptr {
	    void (*destroy) (struct nn_optset *self);
	    int (*setopt) (struct nn_optset *self, int option, const void *optval,
	        size_t optvallen);
	    int (*getopt) (struct nn_optset *self, int option, void *optval,
	        size_t *optvallen);
	};
	struct nn_optset {
	    const struct nn_optset_vfptr *vfptr;
	};
The base class for endpoints. // endpoints的基础类，定义各种网络传输方式，例如"tcp://127.0.0.1:5555"
	struct nn_epbase;
	struct nn_epbase_vfptr {
		// 暂停，允许发送正在传输的信息，完成后通过 nn_epbase_stopped() 函数来通知用户已经暂停了
	    void (*stop) (struct nn_epbase *self); 
	    void (*destroy) (struct nn_epbase *self); // 释放endpoint对象
	};
	struct nn_epbase {
	    const struct nn_epbase_vfptr *vfptr;
	    struct nn_ep *ep;
	};
	void nn_epbase_init (struct nn_epbase *self,
	    const struct nn_epbase_vfptr *vfptr, void *hint); // epbase对象初始化
	void nn_epbase_stopped (struct nn_epbase *self); // 通知用户已经暂停了
	void nn_epbase_term (struct nn_epbase *self); // 终止epbase对象
	struct nn_ctx *nn_epbase_getctx (struct nn_epbase *self); // 返回endpoint对应的异步传输信息 AIO context
	const char *nn_epbase_getaddr (struct nn_epbase *self); // 返回endpoint对应的地址
	void nn_epbase_getopt (struct nn_epbase *self, int level, int option,
	    void *optval, size_t *optvallen); // 返回 socket 选择的值（或者说socket的状态）
	int nn_epbase_ispeer (struct nn_epbase *self, int socktype); // 判断socket的类型是否为socktype
	void nn_epbase_set_error(struct nn_epbase *self, int errnum); // 通知监视系统返回endpoint的错误信息
	void nn_epbase_clear_error(struct nn_epbase *self); // 通知监视系统错误消失
	void nn_epbase_stat_increment(struct nn_epbase *self, int name, int increment); // 在socket结构中增加统计计数
The base class for pipes. // 管道的基础类 管道表示一个连接，一个 endpoint 可以创建多个 pipe
    (for example, bound TCP socket is an endpoint, 
		individual accepted TCP connections are represented by pipes.)
	struct nn_pipebase;
	#define NN_PIPEBASE_RELEASE 1  // 表示接受/发送信息的功能
	#define NN_PIPEBASE_PARSED 2 // flag 表示接受到的信息已经分离到了header和body，防止粘连和重复分离
	struct nn_pipebase_vfptr {
	    int (*send) (struct nn_pipebase *self, struct nn_msg *msg); // 发送信息
	    int (*recv) (struct nn_pipebase *self, struct nn_msg *msg); // 
	};
	struct nn_ep_options{
	    int sndprio;
	    int rcvprio;
	    int ipv4only;
	}; // endpoint详细选项，对nn_pipebase的一些限制
	struct nn_pipebase {
	    struct nn_fsm fsm;
	    const struct nn_pipebase_vfptr *vfptr;
	    uint8_t state;
	    uint8_t instate;
	    uint8_t outstate;
	    struct nn_sock *sock;
	    void *data;
	    struct nn_fsm_event in;
	    struct nn_fsm_event out;
	    struct nn_ep_options options;
	}; // 被core使用
	void nn_pipebase_init (struct nn_pipebase *self, const struct nn_pipebase_vfptr *vfptr, 
		struct nn_epbase *epbase); // 初始化pipe
	void nn_pipebase_term (struct nn_pipebase *self); // 终止pipe
	int nn_pipebase_start (struct nn_pipebase *self); // 连接建立的时候调用该函数
	void nn_pipebase_stop (struct nn_pipebase *self); // 连接断开的时候调用该函数
	void nn_pipebase_received (struct nn_pipebase *self); // 当新消息完全被接受的时候调用该函数
	void nn_pipebase_sent (struct nn_pipebase *self); // 当消息完全发送出去的时候调用该函数
	void nn_pipebase_getopt (struct nn_pipebase *self, int level, int option,
	void *optval, size_t *optvallen); // 返回 socket 选择的值
	int nn_pipebase_ispeer (struct nn_pipebase *self, int socktype); // 判断socket的类型是否为socktype
The transport class. 
	struct nn_transport {
	    const char *name; // 传输类型 "tcp", "ipc", "inproc" etc.
	    int id; // 传输序号
	    void (*init) (void);
	    void (*term) (void);
	    int (*bind) (void *hint, struct nn_epbase **epbase); // 返回: endpoint  hint: 指向nn_epbase_init()  epbase: 用来获取 bind 的地址
	    int (*connect) (void *hint, struct nn_epbase **epbase); // 返回: endpoint  hint: 指向nn_epbase_init()  epbase: 用来获取 connect 的地址
	    struct nn_optset *(*optset) (void); // 创建一个对象来保存确定传输类型的 socket 选项
	    struct nn_list_item item; // 只被 core 使用
	};
```

inproc.h  
------
本地进程内（线程间）传输方式  
```c
//如果是c++，重新定义为c的函数命名方式  不懂
	#ifndef INPROC_H_INCLUDED
	#define INPROC_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_INPROC -1

	#ifdef __cplusplus
	}
	#endif

	#endif
```

ipc.h  
------
进程间通信(Inter-Process Communication)  
```c
// 对象设置  不懂
	#ifndef IPC_H_INCLUDED
	#define IPC_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_IPC -2

	/* The object set here must be valid as long as you are using the socket */
	#define NN_IPC_SEC_ATTR 1
	#define NN_IPC_OUTBUFSZ 2
	#define NN_IPC_INBUFSZ 3

	#ifdef __cplusplus
	}
	#endif

	#endif
```

tcp.h  
------
传输控制协议(Transmission Control Protocol)
```c
	#ifndef TCP_H_INCLUDED
	#define TCP_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_TCP -3

	#define NN_TCP_NODELAY 1

	#ifdef __cplusplus
	}
	#endif

	#endif
```

ws.h  
------
WebSocket protocol 是HTML5一种新的协议  
它实现了浏览器与服务器全双工通信(full-duplex)  
一开始的握手借助HTTP请求完成
可以看看[知乎](https://www.zhihu.com/question/20215561)的解释
```c
	#ifndef WS_H_INCLUDED
	#define WS_H_INCLUDED

	#include "nn.h"

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_WS -4

	/*  NN_WS level socket/cmsg options.  Note that only NN_WSMG_TYPE_TEXT and
	    NN_WS_MSG_TYPE_BINARY messages are supported fully by this implementation.
	    Attempting to set other message types is undefined.  */
	#define NN_WS_MSG_TYPE 1

	/*  WebSocket opcode constants as per RFC 6455 5.2  */
	#define NN_WS_MSG_TYPE_TEXT 0x01
	#define NN_WS_MSG_TYPE_BINARY 0x02

	#ifdef __cplusplus
	}
	#endif

	#endif
```

protocol.h  
------
协议层定义，目的应该是想暴露给用户以实现可扩展，但目前还包含utils下头文件  
```
struct nn_ctx;
Pipe class.
	// 表示该 pipe 当前不可发送和接收消息，
	// 比如在nn_pipe_send()和nn_pipe_recv()返回之后，in()/out()复原之前
	#define NN_PIPE_RELEASE 1
	#define NN_PIPE_PARSED 2 // 表示接受到的信息已经分离到了header和body，防止粘连和重复分离
	// pip产生的事件代号
	#define NN_PIPE_IN 33987
	#define NN_PIPE_OUT 33988
	struct nn_pipe;
	void nn_pipe_setdata (struct nn_pipe *self, void *data); // 协议层发送数据
	void *nn_pipe_getdata (struct nn_pipe *self); // 协议层接收数据
	int nn_pipe_send (struct nn_pipe *self, struct nn_msg *msg); // 发送数据到管道，如果成功，管道就是数据的所有者
	int nn_pipe_recv (struct nn_pipe *self, struct nn_msg *msg); // 从 pipe 里接收信息
	void nn_pipe_getopt (struct nn_pipe *self, int level, int option,
	    void *optval, size_t *optvallen); // 获取 pipe 选择（或者说状态？）
Base class for all socket types.
	struct nn_sockbase;
	#define NN_SOCKBASE_EVENT_IN 1
	#define NN_SOCKBASE_EVENT_OUT 2
	struct nn_sockbase_vfptr {
	    void (*stop) (struct nn_sockbase *self); // 暂停socket
	    void (*destroy) (struct nn_sockbase *self); // 删除socket
	    int (*add) (struct nn_sockbase *self, struct nn_pipe *pipe); // 注册一个新的 pipe
	    void (*rm) (struct nn_sockbase *self, struct nn_pipe *pipe); // 注销管道
	    void (*in) (struct nn_sockbase *self, struct nn_pipe *pipe); // 将 pipe 的状态改为可读
	    void (*out) (struct nn_sockbase *self, struct nn_pipe *pipe); // 将 pipe 的状态改为可写
		int (*events) (struct nn_sockbase *self); // 获取 socket 的状态
		int (*send) (struct nn_sockbase *self, struct nn_msg *msg); // 发送信息到 socket 
		int (*recv) (struct nn_sockbase *self, struct nn_msg *msg); // 从 socket 接收信息
		int (*setopt) (struct nn_sockbase *self, int level, int option,
	        const void *optval, size_t optvallen); // 设置协议信息
		int (*getopt) (struct nn_sockbase *self, int level, int option,
	        void *optval, size_t *optvallen); // 获取协议信息
	};
	struct nn_sockbase {
	    const struct nn_sockbase_vfptr *vfptr;
	    struct nn_sock *sock;
	};
	void nn_sockbase_init (struct nn_sockbase *self,
	    const struct nn_sockbase_vfptr *vfptr, void *hint); // socket base 初始化  hint指向 nn_transport 的 create 函数
	void nn_sockbase_term (struct nn_sockbase *self); // 终止 socket base
	void nn_sockbase_stopped (struct nn_sockbase *self); // 暂停 socket base
	struct nn_ctx *nn_sockbase_getctx (struct nn_sockbase *self); // 获取异步信息
	int nn_sockbase_getopt (struct nn_sockbase *self, int option,
	    void *optval, size_t *optvallen); // 获取 socket base 的状态
	void nn_sockbase_stat_increment (struct nn_sockbase *self, int name,
	    int increment); // 在 socket 结构中增加统计计数
The socktype class.
	#define NN_SOCKTYPE_FLAG_NORECV 1 // 不能接收信息的 socket 类型
	#define NN_SOCKTYPE_FLAG_NOSEND 2 // 不能发送信息的 socket 类型
	struct nn_socktype {
	    // 协议域(族)，常用的协议族有AF_INET、AF_INET6、AF_LOCAL、AF_ROUTE等。协议族决定了socket的地址类型
	    int domain; 
	    int protocol; // 协议 ID 
		int flags; // 状态
		int (*create) (void *hint, struct nn_sockbase **sockbase); // 生成 sockbase
		int (*ispeer) (int socktype); // 判断 socket 类型是否为socktype
		struct nn_list_item item; // 只被 core 使用
	};
```

reqrep.h  
------
allows to build clusters of stateless services to process user requests  
请求/回复模式支持组建大规模的集群服务来处理用户请求
```c
	#ifndef REQREP_H_INCLUDED
	#define REQREP_H_INCLUDED

	#include "nn.h"

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_PROTO_REQREP 3

	#define NN_REQ (NN_PROTO_REQREP * 16 + 0)
	#define NN_REP (NN_PROTO_REQREP * 16 + 1)

	#define NN_REQ_RESEND_IVL 1

	typedef union nn_req_handle {
	    int i;
	    void *ptr;
	} nn_req_handle;

	#ifdef __cplusplus
	}
	#endif

	#endif
```

pubsub.h  
------
distributes messages to large sets of interested subscribers  
扇入模式：支持从多个源聚合请求消息； 
```c
	#ifndef PUBSUB_H_INCLUDED
	#define PUBSUB_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_PROTO_PUBSUB 2

	#define NN_PUB (NN_PROTO_PUBSUB * 16 + 0)
	#define NN_SUB (NN_PROTO_PUBSUB * 16 + 1)

	#define NN_SUB_SUBSCRIBE 1
	#define NN_SUB_UNSUBSCRIBE 2

	#ifdef __cplusplus
	}
	#endif

	#endif
```

bus.h  
------
simple many-to-many communication  
总线模式：简单的多对多的通信；
```c
	#ifndef BUS_H_INCLUDED
	#define BUS_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_PROTO_BUS 7

	#define NN_BUS (NN_PROTO_BUS * 16 + 0)

	#ifdef __cplusplus
	}
	#endif

	#endif
```

pair.h  
------
simple one-to-one communication  
配对模式：简单的一对一的通信
```c
	#ifndef PAIR_H_INCLUDED
	#define PAIR_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_PROTO_PAIR 1

	#define NN_PAIR (NN_PROTO_PAIR * 16 + 0)

	#ifdef __cplusplus
	}
	#endif

	#endif
```

pipeline.h  
------
aggregates messages from multiple sources and load balances them among many destinations  
扇出模式：支持分配到多个节点以支持负载均衡；
```c
	#ifndef PIPELINE_H_INCLUDED
	#define PIPELINE_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_PROTO_PIPELINE 5

	#define NN_PUSH (NN_PROTO_PIPELINE * 16 + 0)
	#define NN_PULL (NN_PROTO_PIPELINE * 16 + 1)

	#ifdef __cplusplus
	}
	#endif

	#endif
```

survey.h  
------
allows to query state of multiple applications in a single go  
调查模式：允许在一个单一的请求里检查多个应用的状态； 
```c
	#ifndef SURVEY_H_INCLUDED
	#define SURVEY_H_INCLUDED

	#ifdef __cplusplus
	extern "C" {
	#endif

	#define NN_PROTO_SURVEY 6

	/*  NB: Version 0 used 16 + 0/1.  That version lacked backtraces, and so
	    is wire-incompatible with this version. */

	#define NN_SURVEYOR (NN_PROTO_SURVEY * 16 + 2)
	#define NN_RESPONDENT (NN_PROTO_SURVEY * 16 + 3)

	#define NN_SURVEYOR_DEADLINE 1

	#ifdef __cplusplus
	}
	#endif

	#endif
```


utils
------
实用工具包，包含基本数据结构（list，queue，hash）互斥（mutex）及原子操作（atomic）等


alloc.c alloc.h
------
```c
	void nn_alloc_init (void); // 可以通过这些函数来实现对内存管理的监听
	void nn_alloc_term (void);
	void *nn_realloc (void *ptr, size_t size);
	void nn_free (void *ptr);
	#define nn_alloc(size, name)
```

atomic.c atomic.h
------
原子操作
```c
	struct nn_atomic {
	#if defined NN_ATOMIC_MUTEX
	    struct nn_mutex sync;
	#endif
	    volatile uint32_t n;
	};
	void nn_atomic_init (struct nn_atomic *self, uint32_t n); // 初始化对象，将其的值设为n
	void nn_atomic_term (struct nn_atomic *self); // 终止对象
	uint32_t nn_atomic_inc (struct nn_atomic *self, uint32_t n); // 给该对象加上n，返回它原来的值
	uint32_t nn_atomic_dec (struct nn_atomic *self, uint32_t n); // 给该对象减去n，返回它原来的值
```

attr.h
------
定义 NN_UNUSED
```c
	#if defined __GNUC__ || defined __llvm__
	#define NN_UNUSED __attribute__ ((unused))
	#else
	#define NN_UNUSED
	#endif
```

chunk.c chunk.h
------
```c
	// 分配 size 个 type 的空间给 result
	int nn_chunk_alloc (size_t size, int type, void **result);
	// 重新分配 size 个 type 的空间给 result
	int nn_chunk_realloc (size_t size, void **chunk);
	// 释放chunk的空间，并减少 chunkref 的 count 值，如果 chunkref 的 count 值等于0，那么解构 chunkref
	void nn_chunk_free (void *p);
	// 将 chunkref 的 count 值加 n
	void nn_chunk_addref (void *p, uint32_t n);
	// 返回 chunk 空间的大小
	size_t nn_chunk_size (void *p);
	// 从chunk开始的地方修建 n bytes，返回指向新chunk的指针
	void *nn_chunk_trim (void *p, size_t n);
```

chunkref.c   chunkref.h
------
这个类表示一个数据块，指向堆上的一块内存，或者直接存着数据（如果数据很小）
```c
	#define NN_CHUNKREF_MAX 32
	struct nn_chunkref {
	    union {
	        uint8_t ref [NN_CHUNKREF_MAX];
			void *unused; // 为了双字节对齐
	    } u;
	};
	// 初始化 chunkref，如果所需要的内存比较小就存在stack上，否则就从堆上分配空间
	void nn_chunkref_init (struct nn_chunkref *self, size_t size); 
	void nn_chunkref_init_chunk (struct nn_chunkref *self, void *chunk); // 从一个chunk对象创建一个chunkref
	void nn_chunkref_term (struct nn_chunkref *self); // 终止 chunkref，回收 chunk 的空间
	/*  Get the underlying chunk. If it doesn't exist (small messages) it allocates
	    one. Chunkref points to empty chunk after the call. */
	void *nn_chunkref_getchunk (struct nn_chunkref *self); // 不懂
	// 把 chunk的内容从 src 移到 des 中，转移前 des 应该为空，转移后 src 的空间被回收
	void nn_chunkref_mv (struct nn_chunkref *dst, struct nn_chunkref *src); 
	// 把 chunk的内容从 src 复制到 des 中，转移前 des 应该为空，转移后 src 的空间不变
	void nn_chunkref_cp (struct nn_chunkref *dst, struct nn_chunkref *src);
	// 返回存在chunk里面的二进制数据
	void *nn_chunkref_data (struct nn_chunkref *self);
	// 返回存在chunk里面的数据大小
	size_t nn_chunkref_size (struct nn_chunkref *self);
	// 从chunk开始的地方修建 n bytes 的数据
	void nn_chunkref_trim (struct nn_chunkref *self, size_t n);
	// 批量复制，效率比nn_chunkref_cp高
	void nn_chunkref_bulkcopy_start (struct nn_chunkref *self, uint32_t copies);
	void nn_chunkref_bulkcopy_cp (struct nn_chunkref *dst, struct nn_chunkref *src);
```

clock.c   clock.h
------
获取当前时间(单位为ms)
```c
	uint64_t nn_clock_ms (void);
```

closefd.c   closefd.h
------
关闭文件描述符
```c
	void nn_closefd (int fd);
```

condvar.c   condvar.h
------
为变量加上互斥锁
```c
	struct nn_condvar {};
	typedef struct nn_condvar nn_condvar_t;
	int nn_condvar_init (nn_condvar_t *cond); // 初始化 condition variable (情况变量??)
	void nn_condvar_term (nn_condvar_t *cond); // 终止 condition variable
	int nn_condvar_wait (nn_condvar_t *cond, nn_mutex_t *lock, int timeout); // 在timeout时间内为cond加上lock互斥锁
	void nn_condvar_signal (nn_condvar_t *cond); // 取消该变量的互斥锁
	void nn_condvar_broadcast (nn_condvar_t *cond); // 取消所有变量的互斥锁
```

cont.h
------
定义nn_cont
```c
	// 指向成员变量的一个指针
	#define nn_cont(ptr, type, member) \
	    (ptr ? ((type*) (((char*) ptr) - offsetof(type, member))) : NULL)
```

efd.c   efd.h
------
```c
	// efd.h
	#if defined NN_USE_EVENTFD
	    #include "efd_eventfd.h"  // 为事件通知创建文件描述符
	#elif defined NN_USE_PIPE
	    #include "efd_pipe.h"  // 为管道创建文件描述符
	#elif defined NN_USE_SOCKETPAIR
	    #include "efd_socketpair.h"  // 为socket连接创建文件描述符
	#elif defined NN_USE_WINSOCK
	    #include "efd_win.h" // 为windows socket连接创建文件描述符
	#else
	    #error
	#endif

	int nn_efd_init (struct nn_efd *self); // 初始化efd
	void nn_efd_stop (struct nn_efd *self); // 暂停efd
	void nn_efd_term (struct nn_efd *self); // 终止efd
	nn_fd nn_efd_getfd (struct nn_efd *self); // 获取efd
	void nn_efd_signal (struct nn_efd *self); // 发送
	void nn_efd_unsignal (struct nn_efd *self); // 接收
	int nn_efd_wait (struct nn_efd *self, int timeout); // 发送信息后等待，直到成功发送信息或者超时
	
	// efd.c
	int nn_efd_wait (struct nn_efd *self, int timeout);
```

efd_eventfd.h   efd_eventfd.inc
------
efd_pipe.h   efd_pipe.inc
------
efd_socketpair.h   efd_socketpair.inc
------
efd_win.h   efd_win.inc
------
具体实现 nn_efd 结构 以及 相关函数
```c
	// .h
	struct nn_efd {
	};
	
	// .inc
	#define NN_EFD_PORT 5907 // 端口
	#define NN_EFD_RETRIES 1000 // 重拨时间
	int nn_efd_init (struct nn_efd *self); // 初始化efd
	void nn_efd_stop (struct nn_efd *self); // 暂停efd
	void nn_efd_term (struct nn_efd *self); // 终止efd
	nn_fd nn_efd_getfd (struct nn_efd *self); // 获取efd
	void nn_efd_signal (struct nn_efd *self); // 发送
	void nn_efd_unsignal (struct nn_efd *self); // 接收
```

err.c    err.h
------
定义一些错误信息
alloc_assert(x)
```c
	// err.h
	// 和系统自带的assert()差不多，但是win32的有点小缺陷
	#define nn_assert(x)
	#define nn_assert_state(obj, state_name) 
	// 检查空间分配是否成功
	#define alloc_assert(x)
	// 检查状态，如果错误则输出错误信息
	#define errno_assert(x)
	// 检查errnum是否为error 不懂
	#define errnum_assert(cond, err)
	// 检查状态，如果失败则输出GetLastError信息
	#define win_assert(x)
	// 检查状态，如果失败则输出WSAGetLastError信息
	#define wsa_assert(x)
	// 为了方便fsm调试而写的assert宏
	#define nn_fsm_error(message, state, src, type)
	#define nn_fsm_bad_action(state, src, type)
	#define nn_fsm_bad_state(state, src, type)
	#define nn_fsm_bad_source(state, src, type)
	// 编译期间的assert
	#define CT_ASSERT_HELPER2(prefix, line)
	#define CT_ASSERT_HELPER1(prefix, line)
	#define CT_ASSERT(x)
	NN_NORETURN void nn_err_abort (void);
	int nn_err_errno (void);
	const char *nn_err_strerror (int errnum);
	void nn_backtrace_print (void);
	#ifdef NN_HAVE_WINDOWS
	int nn_err_wsa_to_posix (int wsaerr);
	void nn_win_error (int err, char *buf, size_t bufsize);
	
	// err.c
	void nn_backtrace_print (void);
	void nn_err_abort (void);
	int nn_err_errno (void);
	const char *nn_err_strerror (int errnum);
	int nn_err_wsa_to_posix (int wsaerr);
	void nn_win_error (int err, char *buf, size_t bufsize);
```

fast.h
------
定义nn_fast(x) nn_slow(x)  
对应linux kernel里的LIKELY和UNLIKELY  
在编译成汇编代码时可以发现  
如果是fast，则执行if后面的语句不需要跳转，执行else后面的语句需要跳转
如果是slow，则执行else后面的语句不需要跳转，执行if后面的语句需要跳转
martin专门写了篇[博客](http://250bpm.com/blog:6)  
说明为什么他要取名为nn_fast和nn_slow，而不用likely和unlikely  
```c
	#if defined __GNUC__ || defined __llvm__
	#define nn_fast(x) __builtin_expect ((x), 1)
	#define nn_slow(x) __builtin_expect ((x), 0)
	#else
	#define nn_fast(x) (x)
	#define nn_slow(x) (x)
	#endif
```

fd.h
------
定义nn_fd 文件描述符的类型
```c
	#ifdef NN_HAVE_WINDOWS
	#include "win.h"
	typedef SOCKET nn_fd;
	#else
	typedef int nn_fd;
	#endif
```

hash.c   hash.h
------
数据结构 -> hash
```c
	#define NN_HASH_ITEM_INITIALIZER {0xffff, NN_LIST_ITEM_INITILIZER} // 用来静态地初始化一个hash元素
	struct nn_hash_item {
	    uint32_t key;
	    struct nn_list_item list;
	}; // 定义每一个hash元素的结构
	struct nn_hash {
	    uint32_t slots;
	    uint32_t items;
	    struct nn_list *array;
	}; // 定义hash表的结构
	void nn_hash_init (struct nn_hash *self); // 初始化hash表
	void nn_hash_term (struct nn_hash *self); // 终止hash
	void nn_hash_insert (struct nn_hash *self, uint32_t key,
	    struct nn_hash_item *item); // 在hash中加入一个元素
	void nn_hash_erase (struct nn_hash *self, struct nn_hash_item *item); // 在hash中删除一个元素
	struct nn_hash_item *nn_hash_get (struct nn_hash *self, uint32_t key); // 输入key返回对应的hash元素
	void nn_hash_item_init (struct nn_hash_item *self); // hash元素初始化，此时该元素不在hash表内
	void nn_hash_item_term (struct nn_hash_item *self); // 终止hash元素， 此时该元素不在hash表内
```

list.c   list.h
------
数据结构 -> 链表
```c
	struct nn_list_item {
	    struct nn_list_item *next;
	    struct nn_list_item *prev;
	}; // 链表每一项的结构
	struct nn_list {
	    struct nn_list_item *first;
	    struct nn_list_item *last;
	}; // 保存链表的头部和尾部
	#define NN_LIST_NOTINLIST ((struct nn_list_item*) -1)/ 初始化不链表里的一个链表元素的未定义的值 不懂
    #define NN_LIST_ITEM_INITIALIZER {NN_LIST_NOTINLIST, NN_LIST_NOTINLIST} // 用来静态地初始化一个链表元素
	void nn_list_init (struct nn_list *self); // 初始化链表
	void nn_list_term (struct nn_list *self); // 终止连表
	int nn_list_empty (struct nn_list *self); //判断链表是否为空
	struct nn_list_item *nn_list_begin (struct nn_list *self); //返回链表头指针
	struct nn_list_item *nn_list_end (struct nn_list *self); // 返回链表尾指针
	struct nn_list_item *nn_list_prev (struct nn_list *self,
	    struct nn_list_item *it); // 返回it前面的一个元素
	struct nn_list_item *nn_list_next (struct nn_list *self,
	    struct nn_list_item *it); // 返回it后面的那个元素
	void nn_list_insert (struct nn_list *self, struct nn_list_item *item,
	    struct nn_list_item *it); // 在it前面插入一个元素
	struct nn_list_item *nn_list_erase (struct nn_list *self,
	    struct nn_list_item *item); // 删除链表当中的一个元素，并返回后一个元素
		void nn_list_item_init (struct nn_list_item *self); // 链表元素的初始化，此时链表元素不在链表内
	void nn_list_item_term (struct nn_list_item *self); // 链表元素的终止，此时链表元素不在链表内
	int nn_list_item_isinlist (struct nn_list_item *self); // 判断一个元素是否在链表内
```

msg.c   msg.h
------
关于信息的一些函数
```c
	struct nn_msg {
		struct nn_chunkref sphdr; // 包含SP信息头
		struct nn_chunkref hdrs; // 包含通信层的信息头
		struct nn_chunkref body; // 包含应用层信息内容
	};
	void nn_msg_init (struct nn_msg *self, size_t size); // 初始化信息，保存长度，只有空的头部
	void nn_msg_init_chunk (struct nn_msg *self, void *chunk); // 通过一大堆指针来初始化信息
	void nn_msg_term (struct nn_msg *self); // 终止信息，释放资源
	void nn_msg_mv (struct nn_msg *dst, struct nn_msg *src); // 将信息从src移到des，然后结构src
	void nn_msg_cp (struct nn_msg *dst, struct nn_msg *src); // 将信息从src复制到des，src任然保留
	void nn_msg_bulkcopy_start (struct nn_msg *self, uint32_t copies); // 大量信息的复制，比nn_msg_cp高效
	void nn_msg_bulkcopy_cp (struct nn_msg *dst, struct nn_msg *src);
	void nn_msg_replace_body(struct nn_msg *self, struct nn_chunkref newBody); // 重写信息body
```

mutex.c   mutex.h
------
在编程中，引入了对象互斥锁的概念，来保证共享数据操作的完整性  
每个对象都对应于一个可称为" 互斥锁" 的标记，这个标记用来保证在任一时刻，只能有一个线程访问该对象
```c
	struct nn_mutex {};
	typedef struct nn_mutex nn_mutex_t;
	void nn_mutex_init (nn_mutex_t *self); // 初始化互斥锁
	void nn_mutex_term (nn_mutex_t *self); // 终止互斥锁
	void nn_mutex_lock (nn_mutex_t *self); // 加锁
	void nn_mutex_unlock (nn_mutex_t *self); // 解锁
```

once.c   once.h
------
让某函数在多线程情况下只执行一次  
posix系统下有实现该功能的函数，windows系统下需要自己定义
```c
	struct nn_once {};
	typedef struct nn_once nn_once_t;
	void nn_do_once (nn_once_t *once, void (*func)(void));
```

queue.c   queue.h
------
数据结构 -> 队列
```c
	#define NN_QUEUE_NOTINQUEUE ((struct nn_queue_item*) -1) // 初始化不队列里的一个队列元素的未定义的值 不懂
	#define NN_QUEUE_ITEM_INITIALIZER {NN_LIST_NOTINQUEUE} // 用来静态地初始化一个队列元素

	struct nn_queue_item {
	    struct nn_queue_item *next;
	}; // 定义队列每一项的结构
	struct nn_queue {
	    struct nn_queue_item *head;
	    struct nn_queue_item *tail;
	}; // 保存队列的头部和尾部
	
	void nn_queue_init (struct nn_queue *self); // 初始化队列
	void nn_queue_term (struct nn_queue *self); // 终止该队列
	int nn_queue_empty (struct nn_queue *self); // 判断队列是否为空
	void nn_queue_push (struct nn_queue *self, struct nn_queue_item *item); // 插入一个元素到队列
	void nn_queue_remove (struct nn_queue *self, struct nn_queue_item *item); // 从队列中移除一个元素
	struct nn_queue_item *nn_queue_pop (struct nn_queue *self); // pop一个元素，若队列为空则返回null
	void nn_queue_item_init (struct nn_queue_item *self); // 初始化队列的一个元素，该元素不在队列内
	void nn_queue_item_term (struct nn_queue_item *self); // 终止队列的一个元素，该元素不在队列内
	int nn_queue_item_isinqueue (struct nn_queue_item *self); // 判断某元素是否在队列内
```

random.c   random.h
------
随机化函数
```c
	void nn_random_seed (); // 生成随机数种子
	void nn_random_generate (void *buf, size_t len); // 生成 len 字节的随机序列
```

sem.c   sem.h
------
Semaphore, 负责协调各个线程, 以保证它们能够正确、合理的使用公共资源。也是操作系统中用于控制进程同步互斥的量。  
这是一个简单的 semaphore, 只有两个值 0: locked   1:unlocked
```c
	struct nn_sem;
	#if defined NN_HAVE_OSX
	#elif defined NN_HAVE_WINDOWS
	#elif defined NN_HAVE_SEMAPHORE
	void nn_sem_init (struct nn_sem *self); // 初始化一个 semaphore，状态为加锁
	void nn_sem_term (struct nn_sem *self); // 终止 semaphore
	void nn_sem_post (struct nn_sem *self); // 为 semaphore 解锁
	int nn_sem_wait (struct nn_sem *self); // 等待 semaphore 解锁后立即加锁
```

sleep.c   sleep.h
------
根据操作系统调用不同的sleep函数，并统一接口
```c
	#ifdef NN_HAVE_WINDOWS
	#else
	void nn_sleep (int milliseconds); // 休眠 milliseconds 
```

stopwatch.c   stopwatch.h
------
检查实际时间是否是期望时间，允许误差下限-10ms，误差上限+50ms
```c
	#define time_assert(actual,expected) \
	    nn_assert (actual > ((expected) - 10000) && actual < ((expected) + 50000));
		
	struct nn_stopwatch {
	    uint64_t start;
	};
	
	#if defined NN_HAVE_WINDOWS
	#else
	void nn_stopwatch_init (struct nn_stopwatch *self); // 设定开始时间
	uint64_t nn_stopwatch_term (struct nn_stopwatch *self); // 获取结束时间，并计算间隔，单位为微秒
```

thread.c   thread.h
------
根据操作系统调用不同的线程头文件，并统一接口
```c
	// thread.h
	typedef void (nn_thread_routine) (void*); // 运行线程，以指针方式调用函数，灵活

	#if defined NN_HAVE_WINDOWS
	#include "thread_win.h"
	#else
	#include "thread_posix.h"
	#endif

	void nn_thread_init (struct nn_thread *self,
	    nn_thread_routine *routine, void *arg); // 初始化线程
	void nn_thread_term (struct nn_thread *self); // 终止线程
	
	// thread.c
	#ifdef NN_HAVE_WINDOWS
	#include "thread_win.inc"
	#else
	#include "thread_posix.inc"
	#endif
```

thread_posix.h   thread_posix.inc
------
posix系统下的线程管理(包括 Mac OSX, linux, unix)
```c
	// thread_posix.h
	struct nn_thread
	{
	    nn_thread_routine *routine;
	    void *arg;
	    pthread_t handle;
	};
	
	// thread_posix.inc
	static void *nn_thread_main_routine (void *arg); // 运行线程
	void nn_thread_init (struct nn_thread *self,
	    nn_thread_routine *routine, void *arg); // 初始化线程
	void nn_thread_term (struct nn_thread *self); // 终止线程
```
thread_win.h   thread_win.inc
------
windows系统下的线程管理
```c
	// thread_win.h
	struct nn_thread
	{
	    nn_thread_routine *routine;
	    void *arg;
	    HANDLE handle;
	};
	
	// thread_win.inc
	static unsigned int __stdcall nn_thread_main_routine (void *arg); // 运行线程
	void nn_thread_init (struct nn_thread *self, 
		nn_thread_routine *routine, void *arg); // 初始化线程
	void nn_thread_term (struct nn_thread *self); // 终止线程
```

win.h
------
windows相关
```c
	#include <windows.h>
	#include <winsock2.h>
	#include <mswsock.h>
	#include <process.h>
	#include <ws2tcpip.h>

	struct sockaddr_un {
	    short sun_family;
	    char sun_path [sizeof (struct sockaddr_storage) -
	        sizeof (short)];
	}; // 这个结构 windows 平台不存在，所以需要构造

	#define ssize_t int
```

wire.h   wire.c
------
网路流处理  
网络协议字节序为big endian，所以也称big endian为网络字节序  
即：最高字节在地址最低位，最低字节在地址最高位，一次排列，较符合人们阅读习惯 
关于字节序内容可参考[wiki](http://en.wikipedia.org/wiki/Endianness)
```c
	uint16_t nn_gets (const uint8_t *buf); // 读取网路流中两个字节入uint16_t 结构中
	void nn_puts (uint8_t *buf, uint16_t val); // 将uint16_t 结构放入网路流中
	uint32_t nn_getl (const uint8_t *buf);  // 读取网路流中四个字节入uint32_t 结构中
	void nn_putl (uint8_t *buf, uint32_t val); // 将uint32_t 结构放入网路流中
	uint64_t nn_getll (const uint8_t *buf); // 读取网路流中四个字节入uint64_t 结构中
	void nn_putll (uint8_t *buf, uint64_t val); // 将uint64_t 结构放入网路流中
```


protocols   协议层实现，包括（REQ/REP:请求/应答；PUB/SUB:发布订阅等.）
		* [ ] bus
			* [ ] bus.c   bus.h
			* [ ] xbus.c   xbus.h
		* [ ] pair
			* [ ] pair.c   pair.h
			* [ ] xpair.c   xpair.h
		* [ ] pipeline
			* [ ] pull.c   pull.h
			* [ ] push.c   push.h
			* [ ] xpull.c   xpull.h
			* [ ] xpush.c   xpush.h
		* [ ] pubsub
			* [ ] pub.c   pub.h
			* [ ] sub.c   sub.h
			* [ ] trie.c   trie.h
			* [ ] xpub.c   xpub.h
			* [ ] xsub.c   xsub.h
		* [ ] reqrep
			* [ ] rep.c   rep.h
			* [ ] req.c   req.h
			* [ ] task.c   task.h
			* [ ] xrep.c   xrep.h
			* [ ] xreq.c   xreq.h
		* [ ] survey
			* [ ] respondent.c   respondent.h
			* [ ] surveyor.c   surveyor.h
			* [ ] xrespondent.c   xrespondent.h
			* [ ] xsurveyor.c   xsurveyor.h
		* [ ] utils
			* [ ] dist.c   dist.h
			* [ ] excl.c   excl.h
			* [ ] fq.c   fq.h
			* [ ] lb.c   lb.h
			* [ ] priolist.c   priolist.h
			
pair.c   pair.h
```c
	// pair.h
	extern struct nn_socktype *nn_pair_socktype;
	
	// pair.c
	static struct nn_socktype nn_pair_socktype_struct = {
	    AF_SP,
	    NN_PAIR,
	    0,
	    nn_xpair_create,
	    nn_xpair_ispeer,
	    NN_LIST_ITEM_INITIALIZER
	};
	struct nn_socktype *nn_pair_socktype = &nn_pair_socktype_struct;
```

xpair.c   xpair.h
```c
	// xpair.h
	extern struct nn_socktype *nn_xpair_socktype;

	int nn_xpair_create (void *hint, struct nn_sockbase **sockbase);
	int nn_xpair_ispeer (int socktype);
	
	// xpair.c
	struct nn_xpair {
	    struct nn_sockbase sockbase;
	    struct nn_excl excl;
	};

	/*  Private functions. */
	static void nn_xpair_init (struct nn_xpair *self,
	    const struct nn_sockbase_vfptr *vfptr, void *hint);
	static void nn_xpair_term (struct nn_xpair *self);

	/*  Implementation of nn_sockbase's virtual functions. */
	static void nn_xpair_destroy (struct nn_sockbase *self);
	static int nn_xpair_add (struct nn_sockbase *self, struct nn_pipe *pipe);
	static void nn_xpair_rm (struct nn_sockbase *self, struct nn_pipe *pipe);
	static void nn_xpair_in (struct nn_sockbase *self, struct nn_pipe *pipe);
	static void nn_xpair_out (struct nn_sockbase *self, struct nn_pipe *pipe);
	static int nn_xpair_events (struct nn_sockbase *self);
	static int nn_xpair_send (struct nn_sockbase *self, struct nn_msg *msg);
	static int nn_xpair_recv (struct nn_sockbase *self, struct nn_msg *msg);
	static int nn_xpair_setopt (struct nn_sockbase *self, int level, int option,
	        const void *optval, size_t optvallen);
	static int nn_xpair_getopt (struct nn_sockbase *self, int level, int option,
	        void *optval, size_t *optvallen);
	static const struct nn_sockbase_vfptr nn_xpair_sockbase_vfptr = {
	    NULL,
	    nn_xpair_destroy,
	    nn_xpair_add,
	    nn_xpair_rm,
	    nn_xpair_in,
	    nn_xpair_out,
	    nn_xpair_events,
	    nn_xpair_send,
	    nn_xpair_recv,
	    nn_xpair_setopt,
	    nn_xpair_getopt
	};

	static void nn_xpair_init (struct nn_xpair *self,
	    const struct nn_sockbase_vfptr *vfptr, void *hint)
	{
	    nn_sockbase_init (&self->sockbase, vfptr, hint);
	    nn_excl_init (&self->excl);
	}

	static void nn_xpair_term (struct nn_xpair *self)
	{
	    nn_excl_term (&self->excl);
	    nn_sockbase_term (&self->sockbase);
	}

	void nn_xpair_destroy (struct nn_sockbase *self)
	{
	    struct nn_xpair *xpair;

	    xpair = nn_cont (self, struct nn_xpair, sockbase);

	    nn_xpair_term (xpair);
	    nn_free (xpair);
	}

	static int nn_xpair_add (struct nn_sockbase *self, struct nn_pipe *pipe)
	{
	    return nn_excl_add (&nn_cont (self, struct nn_xpair, sockbase)->excl,
	        pipe);
	}

	static void nn_xpair_rm (struct nn_sockbase *self, struct nn_pipe *pipe)
	{
	    nn_excl_rm (&nn_cont (self, struct nn_xpair, sockbase)->excl, pipe);
	}

	static void nn_xpair_in (struct nn_sockbase *self, struct nn_pipe *pipe)
	{
	    nn_excl_in (&nn_cont (self, struct nn_xpair, sockbase)->excl, pipe);
	}

	static void nn_xpair_out (struct nn_sockbase *self, struct nn_pipe *pipe)
	{
	    nn_excl_out (&nn_cont (self, struct nn_xpair, sockbase)->excl, pipe);
	}

	static int nn_xpair_events (struct nn_sockbase *self)
	{
	    struct nn_xpair *xpair;
	    int events;

	    xpair = nn_cont (self, struct nn_xpair, sockbase);

	    events = 0;
	    if (nn_excl_can_recv (&xpair->excl))
	        events |= NN_SOCKBASE_EVENT_IN;
	    if (nn_excl_can_send (&xpair->excl))
	        events |= NN_SOCKBASE_EVENT_OUT;
	    return events;
	}

	static int nn_xpair_send (struct nn_sockbase *self, struct nn_msg *msg)
	{
	    return nn_excl_send (&nn_cont (self, struct nn_xpair, sockbase)->excl,
	        msg);
	}

	static int nn_xpair_recv (struct nn_sockbase *self, struct nn_msg *msg)
	{
	    int rc;

	    rc = nn_excl_recv (&nn_cont (self, struct nn_xpair, sockbase)->excl, msg);

	    /*  Discard NN_PIPEBASE_PARSED flag. */
	    return rc < 0 ? rc : 0;
	}

	static int nn_xpair_setopt (NN_UNUSED struct nn_sockbase *self,
	    NN_UNUSED int level, NN_UNUSED int option,
	    NN_UNUSED const void *optval, NN_UNUSED size_t optvallen)
	{
	    return -ENOPROTOOPT;
	}

	static int nn_xpair_getopt (NN_UNUSED struct nn_sockbase *self,
	    NN_UNUSED int level, NN_UNUSED int option,
	    NN_UNUSED void *optval, NN_UNUSED size_t *optvallen)
	{
	    return -ENOPROTOOPT;
	}

	int nn_xpair_create (void *hint, struct nn_sockbase **sockbase)
	{
	    struct nn_xpair *self;

	    self = nn_alloc (sizeof (struct nn_xpair), "socket (pair)");
	    alloc_assert (self);
	    nn_xpair_init (self, &nn_xpair_sockbase_vfptr, hint);
	    *sockbase = &self->sockbase;

	    return 0;
	}

	int nn_xpair_ispeer (int socktype)
	{
	    return socktype == NN_PAIR ? 1 : 0;
	}

	static struct nn_socktype nn_xpair_socktype_struct = {
	    AF_SP_RAW,
	    NN_PAIR,
	    0,
	    nn_xpair_create,
	    nn_xpair_ispeer,
	    NN_LIST_ITEM_INITIALIZER
	};

	struct nn_socktype *nn_xpair_socktype = &nn_xpair_socktype_struct;
```






core   generic code，glue between the pieces
		* [ ] ep.c   ep.h
		* [ ] epbase.c
		* [ ] global.c   global.h
		* [ ] pipe.c
		* [ ] poll.c
		* [ ] sock.c   sock.h
		* [ ] sockbase.c
		* [ ] symbol.c
core
------
核心代码，连接各个模块

global.c   global.h
------
```c
	// global.h
	struct nn_transport *nn_global_transport (int id);// 可以选择通信方式
	struct nn_pool *nn_global_getpool ();// 返回全局线程池
	int nn_global_print_errors();// 输出全局错误信息

	// global.c
	#define NN_MAX_SOCKETS 512// 允许同时发生的 SP sockets 的最大值
	// 为了节省空间，没有被使用的socket应该使用uint16_t来指代每个个体
	// 如果需要超过0x10000个sockets，uint16_t应该改为uint32_t或者int
	CT_ASSERT (NN_MAX_SOCKETS <= 0x10000);

	#define NN_CTX_FLAG_TERMED 1
	#define NN_CTX_FLAG_TERMING 2
	#define NN_CTX_FLAG_TERM (NN_CTX_FLAG_TERMED | NN_CTX_FLAG_TERMING)

	#define NN_GLOBAL_SRC_STAT_TIMER 1

	#define NN_GLOBAL_STATE_IDLE           1
	#define NN_GLOBAL_STATE_ACTIVE         2
	#define NN_GLOBAL_STATE_STOPPING_TIMER 3
	
	struct nn_global {
		// 当前存在的socket的全局表，文件描述符表示socket在这个表的下标
		// 这个指针也用来表示环境是否被初始化
	    struct nn_sock **socks;
	    uint16_t *unused; // 没有被使用的文件描述符的栈
	    size_t nsocks; // 在这个socket表中实际开启的socket数量
	    int flags; // 各种标志的组合
		// 可以被使用的信息传输方式的列表，这个列表不是动态的
		// 在全局初始化的时候就被创建的，之后不能被修改
	    struct nn_list transports;
		struct nn_list socktypes; // 所有socket类型的列表，这个列表也不是动态的
		struct nn_pool pool; // 当前工作的线程池
		int state; // 计时器和其他用来提交数据的机器 不懂
		int print_errors; // 输出错误信息 不懂
	    nn_mutex_t lock; // 互斥锁
	    nn_condvar_t cond; // 环境变量 不懂
	};
	// 包含库的全局状态的一个单独的对象
	static struct nn_global self;
	static nn_once_t once = NN_ONCE_INITIALIZER;
	// 全局环境创建的私有函数
	// （如果是windows系统）初始化socket库
	// 初始化内存管理子系统
	// 为假随机数生成器设定种子
	// 分配SP socket的全局表
	// 如果存在错误信息，就输出
	// 分配未使用的文件描述符的栈空间
	// 初始化传输方式和socket类型的全局状态
	// 添加传输方式inproc,ipc,tcp,ws
	// 添加socket类型pair,xpair,pub,sub,xpub,xsub,rep,req,xrep,xreq,
	// push,xpush,pull,xpull,respondent,surveyor,xrespondent,xsurveyor,bus,xbus
	// 开启工作线程
	static void nn_global_init (void);
	// 全局环境终止的私有函数
	// 如果没有sockets剩余，解构全局环境
	// 关闭工作线程
	// 让所有的transport收回他们的全局资源
	// 从列表中移除socket类型
	// 终止socktypes，transports列表，释放socks的空间，并指向null
	// 关闭内存管理子系统
	// （如果是windows系统）解构socket库
	static void nn_global_term (void);
	// 通信方式和socket类型的私有函数
	static void nn_global_add_transport (struct nn_transport *transport);
	static void nn_global_add_socktype (struct nn_socktype *socktype);
	// 私有函数，统一nn_bind和nn_connect，返回新创建的endpoint的id
	static int nn_global_create_ep (struct nn_sock *, const char *addr, int bind);
	// 私有的socket创建者，不初始化全局状态，自己不会上锁
	static int nn_global_create_socket (int domain, int protocol);
	// 保持socket连接
	static int nn_global_hold_socket (struct nn_sock **sockp, int s);
	static int nn_global_hold_socket_locked (struct nn_sock **sockp, int s);
	static void nn_global_rele_socket(struct nn_sock *);
	int nn_errno (void); // 返回nn_err_errno
	const char *nn_strerror (int errnum); // 返回nn_err_strerror (errnum)
	// 添加flag(NN_CTX_FLAG_TERMING),互斥锁保护
	// nn_close所有的socket
	// 添加flag(NN_CTX_FLAG_TERMED),去掉flag(NN_CTX_FLAG_TERMING),广播环境变量,互斥锁保护
	void nn_term (void); 
	// 等待正在终止的程序完成
	// 去掉flag(NN_CTX_FLAG_TERMED)
	void nn_init (void);
	void *nn_allocmsg (size_t size, int type); // nn_chunk_alloc (size, type, &result);
	void *nn_reallocmsg (void *msg, size_t size); // nn_chunk_realloc (size, &msg); type不变
	int nn_freemsg (void *msg); // nn_chunk_free (msg);
	// 如果没有mhdr，返回null
	// 获取实际数据和数据大小
	// 如果辅助数据分配连一个元素的大小都不够，返回null
	// 如果cmsg被设置为null，那么我们返回第一个属性，否则返回第二个属性
	struct nn_cmsghdr *nn_cmsg_nxthdr_ (const struct nn_msghdr *mhdr, const struct nn_cmsghdr *cmsg);
```



device  
------

device.c   device.h
------
传递信息的设备（不清楚哪里用到了）
Raw Socket 是什么？
Raw Socket的最大特点就是允许用户自己定义packet header，如果这一功能被滥用，就可以被用来实现IP地址欺骗，以及DoS攻击。
Raw Socket不是编程语言级别的标准构造，由OS里面的低层API支持，大多数的网络接口都支持Raw Socket。
通过Raw Socket接收到的数据包带有包头，通过标准Socket只能接收到净载，通过Raw Socket发出数据时，要不要自动生成pocket header是可配置的。
Raw Socket通常用在传输层和网络层。
```
Base class for device.
	struct nn_device_recipe {
		int required_checks; // NN_CHECK标志
		// 入口函数，检查参数，选择作用函数，开启装置，可以重载来实现更多的参数检查
		// 如果两个socket都没有被具体化，错误代码为EBADF
		// 如果只有一个socket，loopback
		// 如果两个socket都是raw，错误代码为EINVAL
		// 如果两个socket的protocol不同，错误代码为EINVAL
		// 获取s1接收，s1发送，s2接收，s2发送的文件描述符
	    int(*nn_device_entry) (struct nn_device_recipe *device, int s1, int s2, int flags);
	    // 双向作用函数，在s1给s2发送消息，s2给s1发送消息时用到
	    int (*nn_device_twoway) (struct nn_device_recipe *device, int s1, int s2);
		// 单向作用函数，在s1给s2发送消息时用到，s1先发到装置里main，装置进行检查后再发给s2
		int (*nn_device_oneway) (struct nn_device_recipe *device, int s1, int s2);
		// 回环函数，如果只有一个socket（这个不太确定，似乎是不断的发回给自己？）
	    int (*nn_device_loopback) (struct nn_device_recipe *device, int s);
		移动信息的函数，将函数从from移到to，中间经过nn_msghdr
	    int (*nn_device_mvmsg) (struct nn_device_recipe *device,
	        int from, int to, int flags);
		// 信息窃听函数，这个函数使你可以修改或者取消信息因为从一个socket到达另一个socket时必定会经过这个函数
		// 返回值  1:继续传递信息  0:停止传送信息   －1:有错误，设置错误信息
	    int (*nn_device_rewritemsg) (struct nn_device_recipe *device,
	        int from, int to, int flags, struct nn_msghdr *msghdr, int bytes);
	};
```

其他文件
------ 

CMakeLists.txt 
------ 
cmake编译文件，根据操作系统选择相应的文件进行编译形成动态库文件

pkgconfig.in
------   
pkconfig工具配置文件

README
------
包括  
Welcome  
Prerequisites  
Build it with CMake  
Resources  
