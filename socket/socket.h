/*
 * net.h，孙小强，2016年11月30日17:08:11
 * struct socket 结构体的定义
 * line 00076
 */
 
struct socket {
	socket_state          	state;
	
#if 0
/* net.h */
00048 typedef enum {
00049         SS_FREE = 0,         /* 该套接字尚未分配，未使用                */
00050         SS_UNCONNECTED,      /* 该套接字未连接任何一个对端的套接字    */
00051         SS_CONNECTING,       /* 正在连接过程中     */
00052         SS_CONNECTED,        /* 已经连接一个套接字          */
00053         SS_DISCONNECTING     /* 正在断开连接的过程中  */
00054 } socket_state;
#endif 

	unsigned long		  	flags;

#if 0
/*net.h*/
00060 #define SOCK_ASYNC_NOSPACE      0 /*标识该套接字的发送队列是否已满*/
00061 #define SOCK_ASYNC_WAITDATA     1 /*标识应用程序通过 recv 调用时，是否在等待数据的接收*/
00062 #define SOCK_NOSPACE            2 /*标识非异步的情况下盖套接字的发送队列是否已满*/
#endif

	const struct proto_ops	*ops;

#if 0
/*net.h*/
00095 struct proto_ops {
00096         int             family;	/*协议族*/
00097         struct module   *owner;	/*所属模块*/
00098         int             (*release)   (struct socket *sock);	/*一组与套接字系统调用相应的传输层函数指针*/
......	/*同上，省略*/
00131 };
#endif

	struct fasync_struct  	*fasync_list;

#if 0
/*存储了异步通知队列*/
#endif

	struct file		      	*file;

#if 0
/*指向与该套接字相关的 file 结构的指针*/
#endif

	struct sock		      	*sk;

#if 0
/*指向了与该套接字关联的传输控制块*/
#endif	

	wait_queue_head_t     	wait;

#if 0
/*等待该套接字的进程队列*/
#endif	

	short			      	type;
	
#if 0
/*net.h*/
enum sock_type {
	SOCK_STREAM	= 1,		/*基于连接的套接字*/
	SOCK_DGRAM	= 2,		/*基于数据报的套接字*/
	SOCK_RAW	= 3,		/*原始套接字*/
	SOCK_RDM	= 4,		/*可靠传输报文套接字*/
	SOCK_SEQPACKET	= 5,	/*顺序分组套接字*/
	SOCK_DCCP	= 6,		/*数据报拥塞控制协议套接字*/
	SOCK_PACKET	= 10,		/*混杂模式套接字*/
};
#endif
};


/*
 * net.h，孙小强，2016年11月30日17:25:54
 * struct proto_ops 结构体的定义
 * line 00095
 */
struct proto_ops {
    int             family;

#if 0
/*socket.h*/
00152 #define AF_UNSPEC       0
00153 #define AF_UNIX         1       /* Unix domain sockets          */
00154 #define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
00155 #define AF_INET         2       /* Internet IP Protocol         */
...
00181 #define AF_MAX          32      /* For now.. */
...
#endif

    struct module   *owner;

#if 0
/*用来表示所属模块的 module 结构体指针*/
#endif

    int             (*release)   (struct socket *sock);
    int             (*bind)      (struct socket *sock,
                                  struct sockaddr *myaddr,
                                  int sockaddr_len);
    int             (*connect)   (struct socket *sock,
                                  struct sockaddr *vaddr,
                                  int sockaddr_len, int flags);
    int             (*socketpair)(struct socket *sock1,
                                  struct socket *sock2);
    int             (*accept)    (struct socket *sock,
                                  struct socket *newsock, int flags);
    int             (*getname)   (struct socket *sock,
                                  struct sockaddr *addr,
                                  int *sockaddr_len, int peer);
    unsigned int    (*poll)      (struct file *file, struct socket *sock,
                                  struct poll_table_struct *wait);
    int             (*ioctl)     (struct socket *sock, unsigned int cmd,
                                  unsigned long arg);
    int             (*listen)    (struct socket *sock, int len);
    int             (*shutdown)  (struct socket *sock, int flags);
    int             (*setsockopt)(struct socket *sock, int level,
                                  int optname, char __user *optval, int optlen);
    int             (*getsockopt)(struct socket *sock, int level,
                                  int optname, char __user *optval, int __user *optlen);
    int             (*sendmsg)   (struct kiocb *iocb, struct socket *sock,
                                  struct msghdr *m, size_t total_len);
    int             (*recvmsg)   (struct kiocb *iocb, struct socket *sock,
                                  struct msghdr *m, size_t total_len,
                                  int flags);
    int             (*mmap)      (struct file *file, struct socket *sock,
                                  struct vm_area_struct * vma);
    ssize_t         (*sendpage)  (struct socket *sock, struct page *page,
                                  int offset, size_t size, int flags);
#if 0
/*
 * 以上，是一组与系统调用相对应的传输层函数指针。
 * 因此整个 proto_ops 结构体可以看做是一张套接字系统调用到传输层函数的跳转表。
 * 其中某些操作会继续通过 proto 结构跳转，进入具体的传输层或者网络层的处理。
 * 
 * proto_ops 结构体是与协议无关的套接字层到协议相关的传输层的转接
 * proto     结构体是传输层映射到网络层的转换
 * 
 * proto_ops 结构体的初始化与一下两个数据结构有关
 *           1. inet_protosw 结构体数组 inetsw_array[]
 *           2. list_head    结构体数组 inetsw[]
 */
#endif
};



/*
 * protocol.h，孙小强，2016年11月30日18:05:23
 * struct inet_protosw 结构体的定义
 * line 00095
 */
struct inet_protosw {
    struct list_head list;

#if 0
/*list_head 结构体用来将该结构体连接成一个双向链表，用来查询*/
#endif

    unsigned short   type;     /* This is the 2nd argument to socket(2). */

#if 0
/*net.h*/
1. 该类型与socket() 系统调用的第二个参数相同
2. 与 socket 结构体中 type 的可取值相同
#endif

    int              protocol;

#if 0
/*Linux/include/uapi/linux/in.h*/
enum {
28   IPPROTO_IP = 0,               /* Dummy protocol for TCP               */
36   IPPROTO_TCP = 6,              /* Transmission Control Protocol        */
42   IPPROTO_UDP = 17,             /* User Datagram Protocol               */
79 };
#endif

    struct proto     *prot;

#if 0
/*proto     结构体是传输层映射到网络层的转换*/
#endif

    struct proto_ops *ops;

#if 0
/*proto_ops 结构体是与协议无关的套接字层到协议相关的传输层的转接*/
#endif

    int              capability; 

#if 0
/*操作这类别套接字所需要的权限*/
#endif

    char             no_check;   

#if 0
/*套接字对应的传输模块是否需要校验*/
#endif

    unsigned char    flags; 

#if 0
00078 #define INET_PROTOSW_REUSE 0x01      /* 端口可重用 */
00079 #define INET_PROTOSW_PERMANENT 0x02  /* 永久协议不可以被移除 */
#endif
};




00881 struct proto_ops inet_stream_ops = {
00882         .family =       PF_INET,
00883         .owner =        THIS_MODULE,
00884         .release =      inet_release,
00885         .bind =         inet_bind,
00886         .connect =      inet_stream_connect,
00887         .socketpair =   sock_no_socketpair,
00888         .accept =       inet_accept,
00889         .getname =      inet_getname,
00890         .poll =         tcp_poll,
00891         .ioctl =        inet_ioctl,
00892         .listen =       inet_listen,
00893         .shutdown =     inet_shutdown,
00894         .setsockopt =   inet_setsockopt,
00895         .getsockopt =   inet_getsockopt,
00896         .sendmsg =      inet_sendmsg,
00897         .recvmsg =      inet_recvmsg,
00898         .mmap =         sock_no_mmap,
00899         .sendpage =     tcp_sendpage
00900 };
00901 
00902 struct proto_ops inet_dgram_ops = {
00903         .family =       PF_INET,
00904         .owner =        THIS_MODULE,
00905         .release =      inet_release,
00906         .bind =         inet_bind,
00907         .connect =      inet_dgram_connect,
00908         .socketpair =   sock_no_socketpair,
00909         .accept =       sock_no_accept,
00910         .getname =      inet_getname,
00911         .poll =         datagram_poll,
00912         .ioctl =        inet_ioctl,
00913         .listen =       sock_no_listen,
00914         .shutdown =     inet_shutdown,
00915         .setsockopt =   inet_setsockopt,
00916         .getsockopt =   inet_getsockopt,
00917         .sendmsg =      inet_sendmsg,
00918         .recvmsg =      inet_recvmsg,
00919         .mmap =         sock_no_mmap,
00920         .sendpage =     inet_sendpage,
00921 };
00922 
00923 struct net_proto_family inet_family_ops = {
00924         .family = PF_INET,
00925         .create = inet_create,
00926         .owner  = THIS_MODULE,
00927 };

2325 struct proto tcp_prot = {
2326         .name                   = "TCP",
2327         .owner                  = THIS_MODULE,
2328         .close                  = tcp_close,
2329         .connect                = tcp_v4_connect,
2330         .disconnect             = tcp_disconnect,
2331         .accept                 = inet_csk_accept,
2332         .ioctl                  = tcp_ioctl,
2333         .init                   = tcp_v4_init_sock,
2334         .destroy                = tcp_v4_destroy_sock,
2335         .shutdown               = tcp_shutdown,
2336         .setsockopt             = tcp_setsockopt,
2337         .getsockopt             = tcp_getsockopt,
2338         .recvmsg                = tcp_recvmsg,
2339         .sendmsg                = tcp_sendmsg,
2340         .sendpage               = tcp_sendpage,
2341         .backlog_rcv            = tcp_v4_do_rcv,
2342         .release_cb             = tcp_release_cb,
2343         .hash                   = inet_hash,
2344         .unhash                 = inet_unhash,
2345         .get_port               = inet_csk_get_port,
2346         .enter_memory_pressure  = tcp_enter_memory_pressure,
2347         .stream_memory_free     = tcp_stream_memory_free,
2348         .sockets_allocated      = &tcp_sockets_allocated,
2349         .orphan_count           = &tcp_orphan_count,
2350         .memory_allocated       = &tcp_memory_allocated,
2351         .memory_pressure        = &tcp_memory_pressure,
2352         .sysctl_mem             = sysctl_tcp_mem,
2353         .sysctl_wmem            = sysctl_tcp_wmem,
2354         .sysctl_rmem            = sysctl_tcp_rmem,
2355         .max_header             = MAX_TCP_HEADER,
2356         .obj_size               = sizeof(struct tcp_sock),
2357         .slab_flags             = SLAB_DESTROY_BY_RCU,
2358         .twsk_prot              = &tcp_timewait_sock_ops,
2359         .rsk_prot               = &tcp_request_sock_ops,
2360         .h.hashinfo             = &tcp_hashinfo,
2361         .no_autobind            = true,
2362 #ifdef CONFIG_COMPAT
2363         .compat_setsockopt      = compat_tcp_setsockopt,
2364         .compat_getsockopt      = compat_tcp_getsockopt,
2365 #endif
2366         .diag_destroy           = tcp_abort,
2367 };


2195 struct proto udp_prot = {
2196         .name              = "UDP",
2197         .owner             = THIS_MODULE,
2198         .close             = udp_lib_close,
2199         .connect           = ip4_datagram_connect,
2200         .disconnect        = udp_disconnect,
2201         .ioctl             = udp_ioctl,
2202         .destroy           = udp_destroy_sock,
2203         .setsockopt        = udp_setsockopt,
2204         .getsockopt        = udp_getsockopt,
2205         .sendmsg           = udp_sendmsg,
2206         .recvmsg           = udp_recvmsg,
2207         .sendpage          = udp_sendpage,
2208         .backlog_rcv       = __udp_queue_rcv_skb,
2209         .release_cb        = ip4_datagram_release_cb,
2210         .hash              = udp_lib_hash,
2211         .unhash            = udp_lib_unhash,
2212         .rehash            = udp_v4_rehash,
2213         .get_port          = udp_v4_get_port,
2214         .memory_allocated  = &udp_memory_allocated,
2215         .sysctl_mem        = sysctl_udp_mem,
2216         .sysctl_wmem       = &sysctl_udp_wmem_min,
2217         .sysctl_rmem       = &sysctl_udp_rmem_min,
2218         .obj_size          = sizeof(struct udp_sock),
2219         .h.udp_table       = &udp_table,
2220 #ifdef CONFIG_COMPAT
2221         .compat_setsockopt = compat_udp_setsockopt,
2222         .compat_getsockopt = compat_udp_getsockopt,
2223 #endif
2224         .clear_sk          = sk_prot_clear_portaddr_nulls,
2225 };


921 struct proto raw_prot = {
922         .name              = "RAW",
923         .owner             = THIS_MODULE,
924         .close             = raw_close,
925         .destroy           = raw_destroy,
926         .connect           = ip4_datagram_connect,
927         .disconnect        = udp_disconnect,
928         .ioctl             = raw_ioctl,
929         .init              = raw_init,
930         .setsockopt        = raw_setsockopt,
931         .getsockopt        = raw_getsockopt,
932         .sendmsg           = raw_sendmsg,
933         .recvmsg           = raw_recvmsg,
934         .bind              = raw_bind,
935         .backlog_rcv       = raw_rcv_skb,
936         .release_cb        = ip4_datagram_release_cb,
937         .hash              = raw_hash_sk,
938         .unhash            = raw_unhash_sk,
939         .obj_size          = sizeof(struct raw_sock),
940         .h.raw_hash        = &raw_v4_hashinfo,
941 #ifdef CONFIG_COMPAT
942         .compat_setsockopt = compat_raw_setsockopt,
943         .compat_getsockopt = compat_raw_getsockopt,
944         .compat_ioctl      = compat_raw_ioctl,
945 #endif
946 };


static struct inet_protosw inetsw_array[] =
{
    {
         .type =       SOCK_STREAM,
         .protocol =   IPPROTO_TCP,
         .prot =       &tcp_prot,
         .ops =        &inet_stream_ops,
         .capability = -1,
         .no_check =   0,
         .flags =      INET_PROTOSW_PERMANENT,
    },

    {
         .type =       SOCK_DGRAM,
         .protocol =   IPPROTO_UDP,
         .prot =       &udp_prot,
         .ops =        &inet_dgram_ops,
         .capability = -1,
         .no_check =   UDP_CSUM_DEFAULT,
         .flags =      INET_PROTOSW_PERMANENT,
   },
    

   {
        .type =       SOCK_RAW,
        .protocol =   IPPROTO_IP,        /* wild card */
        .prot =       &raw_prot,
        .ops =        &inet_dgram_ops,
        .capability = CAP_NET_RAW,
        .no_check =   UDP_CSUM_DEFAULT,
        .flags =      INET_PROTOSW_REUSE,
   }
};




/*
 * socket.c，孙小强，2016年12月02日23:27:29
 * sock_fs_type 结构体的定义
 * line 332
 * 功能：
 *      1. 每一种文件都有各自的文件类型，套接字关联的文件类型为套接字文件
 *      2. 该结构使套接字和文件描述符关联，并支持特殊套接字层的 i 节点的分配和释放
 */

static struct file_system_type sock_fs_type = {
    .name =         "sockfs",

/*文件系统类型*/

    .mount =        sockfs_mount,

/*提供分配超级块的接口实现*/

    .kill_sb =      kill_anon_super,

/*提供释放超级块的接口实现*/
};


/*
 * socket.c，孙小强，2016年12月02日23:36:13
 * sockfs_ops 结构体的定义
 * line 304
 * 功能：
 *      1.定义了套接字文件系统的操作接口
 *      2.支持具体的接口有 i 节点的分配、释放、获取文件系统的状态信息
 */
static const struct super_operations sockfs_ops = {
    .alloc_inode    = sock_alloc_inode,

/*
 *   sock_alloc_inode() 
 *   套接字文件系统的 i 节点的分配函数
 */

    .destroy_inode  = sock_destroy_inode,

/*
 *   sock_destroy_inode()
 *  套接字文件系统的 i 节点释放函数
 */    
    .statfs         = simple_statfs,

/*
 *   simple_statfs()
 *   获取套接字文件系统的状态信息函数
 */

};