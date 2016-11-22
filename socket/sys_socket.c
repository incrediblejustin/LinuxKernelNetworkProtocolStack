
/*sys_socket(), 孙小强，2016年11月18日20:00:33
 * 
 * 1. 创建一个 `struct socket` 类型的指针 `sock`
 * 2. 将 `sock` 的地址传入 `sock_create()`
 * 	- `sock_create()`函数内部调用 `__sock_create()`
 * 		- 首先调用`sock_alloc()`
 * 		- 调用`pf->create()`
 * 			- `sk_alloc()`
 * 			- `sk->sk_prot->hash()`, TCP: `tcp_v4_hash()`, RAW: `raw_v4_hash()`
 * 			- `sk->sk_prot->init()`, TCP: `tcp_v4_init_sock()`, RAW: `raw_init()`
 * 	- `sock_map_fd()` 为创建好的套接字分配一个文件描述符，并绑定
 * 3. 返回错误值
 * 
 */
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	int retval;
	struct socket *sock; // 1
	int flags;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	retval = sock_create(family, type, protocol, &sock);  // 2
	if (retval < 0)
		goto out;


	retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
	if (retval < 0)
		goto out_release;
		
out:
	/* It may be already another descriptor 8) Not kernel problem. */
	return retval; // 3

out_release:
	sock_release(sock);
	return retval; // 3
}

/*sock_create(), 孙小强，2016年11月18日20:04:17

调用了__sock_create()

*/
int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}

/*__sock_create(), 孙小强， 2016年11月18日20:05:29
 * 
 * 1. 检查`family`， `type` 是否合法范围内
 * 2. 由于`SOCK_PACKET`类型的套接字已经废除， 而在系统外增加一个`PF_PACKET`类型的协议族，将前者强转成后者
 * 3. 安全模块对台阶自的创建做检查 , `security_socket_create()`
 * 4. `sock_alloc()` 在 `sock_inode_cache` 缓存中分配 **i节点** 和 **套接字**，同时初始化 i节点 和 套接字（ **i节点用来标识此文件并与套接字关联，让套接字可以向一般的文件对他进行读写）**，如果分配失败则会给出警告：`socket: no more sockets`，并根*据套接字的类型参数设置创建的套接字的类型*
 * 5. 根据参数`family` 获取已经注册在`net_families`中的对应的`net_proto_family`指针( **pf** ),*需要读写锁的保护*
 * 6. `try_module_get(net_families[family])`,`family` 标识的类型的协议族`net_proto_family`是以内核模块加载并**动态**注册到net_families中，则需要对内核模块引用计数加一，防止创建过程中此内核模块被动态卸载， 并对读写锁解锁
 * 7. `pf->create(sock, protocol)`, 继续对套接字初始化（调用IPv4协议族中的**inet_create()**），同时创建传输控制块
 * 8. `try_module_get(sock->ops->owner)`, 如果`sock->ops`是以内核模块的方式动态加载，并且注册到内核中的，则需要对内核模块引用计数加一（ ），防止创建过程中此内核模块被动态卸载
 * 9. `module_put(pf->owner)`, 完成对IPv4协议族中的`inet_create()`调用完后，对模块的引用计数减一, 进行一系列错误检查创建完成
 * 
 */
static int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
	 *      Check protocol is in range
	 */
	if (family < 0 || family >= NPROTO) // 1
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

	   This uglymoron is moved from INET layer to here to avoid
	   deadlock in module load.
	 */
	if (family == PF_INET && type == SOCK_PACKET) { // 2
		static int warned;
		if (!warned) {
			warned = 1;
			printk(KERN_INFO "%s uses obsolete (PF_INET,SOCK_PACKET)\n",
			       current->comm);
		}
		family = PF_PACKET;
	}

	err = security_socket_create(family, type, protocol, kern); // 3
	if (err)
		return err;

	/*
	 *	Allocate the socket and allow the family to set things up. if
	 *	the protocol is 0, the family is instructed to select an appropriate
	 *	default.
	 */
	sock = sock_alloc(); // 4
	if (!sock) {
		if (net_ratelimit())
			printk(KERN_WARNING "socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
				   closest posix thing */
	}

	sock->type = type;

#ifdef CONFIG_MODULES
	/* Attempt to load a protocol module if the find failed.
	 *
	 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user
	 * requested real, full-featured networking support upon configuration.
	 * Otherwise module support will break!
	 */
	if (net_families[family] == NULL)
		request_module("net-pf-%d", family);
#endif

	rcu_read_lock();
	pf = rcu_dereference(net_families[family]); // 5
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	if (!try_module_get(pf->owner)) // 6
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	err = pf->create(net, sock, protocol, kern);  // 7 ****
	if (err < 0)
		goto out_module_put;

	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */
	if (!try_module_get(sock->ops->owner)) // 8
		goto out_module_busy;

	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	module_put(pf->owner); // 9
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_sock_release;
	*res = sock;

	return 0;

out_module_busy:
	err = -EAFNOSUPPORT;
out_module_put:
	sock->ops = NULL;
	module_put(pf->owner);
out_sock_release:
	sock_release(sock);
	return err;

out_release:
	rcu_read_unlock();
	goto out_sock_release;
}



/*inet_create(), 孙小强， 2016年11月18日20:08:50
 *
 *1. 	`sock->state = SS_UNCONNECTED`, 将套接字的状态注册成**SS_UNCONNECTED**
 *2. `list_for_each_rcu(),`**将sock->type作为关键字遍历inetsw散列表**
 *3. `list_entry()`，通过计算偏移的方法获取指向 inet_protosw 的结果的指针
 *4. 根据参数类型获取匹配的 inet_protosw 结构体的实例
 *5. 如果不能再 inetsw中获得匹配的inet_protosw 结构的实例，则需加载相应的内核模块，再返回第五步，（最多尝试两次，失败则会退出）
 *6. 判断当前进程是否有*answer->capability*（保存在进程的描述符中国）的能力，如果没有则不能创建套接字
 *7. `sock->ops = answer->ops`, 用来设置套接字层 和 传输层之间的接口ops
 *8. `sk_alloc()`, 用来**分配一个传输控制块**，返回值放在**sk**中
 *9. 设置传输模块是否需要校验(**sk->sk_no_check**) 和 是否可以重用地址和端口标志（**sk->sk_reuse**）
 *10. 设置**inet_sock**块(** *inet**)中的**is_icsk,** 用来标识是否为面向连接的传输控制块
 *11. 如果套接字为原始类型，则设置本地端口为协议号 并且 inet->hdrincl 表示需要自己构建 IP 首部
 *12. 设置传输模块是否支持 PMTU(动态发现因特网上任意一条路径的最大传输单元(MTU)的技术)
 *13. `sock_init_data(sock, sk)`, 对传输控制块进行了初始化。
 *14. 初始化**sk->destruct**, 在套接字释放时回调，用来清理和回收资源，设置传输控制字协议族(**sk->sk_family**)和协议号标识(**sk->sk_protocol**)
 *15. 设置传输控制块 单播的TTL, 是否法相回路标志，组播TTL, 组播使用的本地接口索引，传输控制块组播列表
 *16. 如果传输控制块中的num设置了本地端口号，则设置传输控制块中的sport网络字节序格式的本地端口号； **调用传输层接口上的hash(),把传输控制块加入到管理的散列表中**；（TCP: `tcp_v4_hash()`, UDP:`udp_lib_hash()`）
 *17. 如果sk->sk_prot->init指针已经被设置，则会调用sk->sk_prot->init(sk)来进行具体传输控制块的初始化（TCP: `tcp_v4_init_sock()`,无UDP）
 *
 */
static int inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	char answer_no_check;
	int try_loading_module = 0;
	int err;

	if (unlikely(!inet_ehash_secret))
		if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
			build_ehash_secret();

	sock->state = SS_UNCONNECTED; // 1

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetsw[sock->type], list) { // 2, 3

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) { //  4
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (unlikely(err)) { // 5
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INET, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INET, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	if (sock->type == SOCK_RAW && !kern && !capable(CAP_NET_RAW)) // 6
		goto out_rcu_unlock;

	err = -EAFNOSUPPORT;
	/*
	 * ¼ì²éÍøÂçÃüÃû¿Õ¼ä£¬¼ì²éÖ¸¶¨µÄÐ­ÒéÀàÐÍ
	 * ÊÇ·ñÒÑ¾­Ìí¼Ó£¬²Î¼ûinit_inet()£¬tcpÐ­Òé¶ÔÓ¦
	 * µÄnet_protocolÊµÀýÊÇtcp_protocol¡£
	 */
	if (!inet_netns_ok(net, protocol))
		goto out_rcu_unlock;

	sock->ops = answer->ops; // 7
	answer_prot = answer->prot;
	answer_no_check = answer->no_check;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(answer_prot->slab == NULL);

	err = -ENOBUFS;

	sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot); // 8
	if (sk == NULL)
		goto out;

	err = 0;
	sk->sk_no_check = answer_no_check; // 9 
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = 1;

	inet = inet_sk(sk); // 10
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	if (SOCK_RAW == sock->type) { // 11
		inet->inet_num = protocol;
		if (IPPROTO_RAW == protocol)
			inet->hdrincl = 1;
	}

	if (ipv4_config.no_pmtu_disc) // 12
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	inet->inet_id = 0;

	sock_init_data(sock, sk); // 13

	sk->sk_destruct	   = inet_sock_destruct; // 14
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1; // 15
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;

	sk_refcnt_debug_inc(sk);

	if (inet->inet_num) {
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->inet_sport = htons(inet->inet_num);
		/* Add to protocol hash chains. */
		sk->sk_prot->hash(sk);    // 16
	}

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk); // 17
		if (err)
			sk_common_release(sk);
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}


/*sys_bind(), 孙小强, 2016年11月19日23:48:53
 * 
 * 1. 首先创建 **struct socket** 类型的指针 **sock**
 * 2. `sockfd_lookup_light()`,  根据文件描述符 **fd** 获取套接字的指针， 并且返回是否需要对文件引用计数的标志
 * 3. `move_addr_to_kernel(umyaddr, addrlen, address)`,  **address**字符型数组用来保存地址从用户空间传进来的绑定地址
 * 4. `security_socket_bind()`，安全模块对套接字bind做检查
 * 5. `sock->ops->bind()`, 在 **inet_create()** 第 8 步中设置了套接字层与传输层之间的接口 **ops** ,所有类型的套接字的 bind 接口是统一的即 `inet_bind()` ，他将实现传输层接口 bind 的有关调用
 * 	- **RAW:** `sk->sk_prot->bind()` ---> `raw_bind()`
 * 	- **TCP/UDP:** `sk->sk_prot->get_port()`
 * 		- **TCP:** `tcp_v4_get_port()`
 * 		- **UCP:** `rdp_v4_get_port()`
 * 6. `fput_light()`, 根据第二步中获得标志， 对文件的引用计数进行操作
 * 
*/
SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{
	struct socket *sock; // 1
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed); // 2 
	if (sock) {
		err = move_addr_to_kernel(umyaddr, addrlen, (struct sockaddr *)&address); // 3
		if (err >= 0) {
			err = security_socket_bind(sock,
						   (struct sockaddr *)&address,
						   addrlen); // 4
			if (!err)
				err = sock->ops->bind(sock,
						      (struct sockaddr *)
						      &address, addrlen);  // 5
		}
		fput_light(sock->file, fput_needed); // 6
	}
	return err;
}


/*inet_bind(), 孙小强， 2016年11月19日23:50:51
 * 
 * 1. **addr**、**sk** 、**inet**指针， 分别是`（struct socketaddr_in）uaddr`、`sock->sk` 、`inet_sk(sk)`
 * 2. `sk->sk_prot`, 在`inet_create()` 中 `sk_alloc()` 中被初始化，如果是TCP套接字该值就是**tcp_prot**，只有RAW 类型（**SOCK_RAW**）的套接字才可以直接调用传输层接口上的 bind()， 即当前套接字在传输层接口上有 bind 的实现( `raw_bind()` )，`sk->sk_prot->bind` 为真，完成后可以直接返回
 * 3. 若没有 bind 的实现，则需要对绑定地址的长度进行合法性检查
 * 4. `inet_addr_type(addr->sin_addr.sin_addr)`， 根据**绑定地址中的地址参数**得到地址的类型(组播，广播，单播...)
 * 5. 对上一步得到的地址类型进行检查，判断是否可以进行地址和端口的绑定
 * 6. 将绑定地址中的网络字节序的端口号转换成本机的字节序，并对端口进行合法性校验，并且还要判断是否允许绑定小于1024的特权端口，保存在 **snum** 中
 * 7. `sk->sk_state != TCP_CLOSE || inet->inet_num`, 如果套接字的状态不是TCP_CLOSE或者已经是绑定过的套接字则会返回错误
 * 8. `inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr`,   将传入的绑定地址设置到传输控制块中
 * 9. `sk->sk_prot->get_port(sk, snum)`,  调用传输层 `get_port`进行具体的传输层的地址绑定，该 **get_port()** 对应的**TCP:** `tcp_v4_get_port()`, **UCP:** `rdp_v4_get_port()`
 * 10. `sk->sk_userlocks |= SOCK_BINDADDR_LOCK;sk->sk_userlocks |= SOCK_BINDPORT_LOCK;`   标识了传输控制块已经绑定了 **本地地址** 和 **本地端口**
 * 11. `inet->sport = htons(inet->num)` 设置本地端口.   再初始化目的地址和目的端口为0
 * 
 */
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr; // 1
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	unsigned short snum;
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) { // 2
		err = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}
	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in)) // 3
		goto out;

	chk_addr_ret = inet_addr_type(sock_net(sk), addr->sin_addr.s_addr); // 4

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	if (!sysctl_ip_nonlocal_bind && // 5
	    !(inet->freebind || inet->transparent) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	snum = ntohs(addr->sin_port); // 6
	err = -EACCES;
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE)) 
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */

	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num) // 7
		goto out_release_sock;

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr; // 8
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	if (sk->sk_prot->get_port(sk, snum)) { // 9
		inet->inet_saddr = inet->inet_rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	if (inet->inet_rcv_saddr) // 10
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->inet_sport = htons(inet->inet_num); // 11
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}



/*sys_socket(), 孙小强，2016年11月20日22:41:44
 * 
 * 1. 首先创建 **struct socket** 类型的指针 **sock**
 * 2. `sockfd_lookup_light()`,  根据文件描述符 **fd** 获取套接字的指针， 并且返回是否需要对文件引用计数的标志
 * 3. 如果 backlog 的值大于系统设置的门限值( 128 )，将 backlog 设为系统门限的最大值
 * 4. 安全模块对套接字的 listen 做检查
 * 5. 通过套接字与接口层的接口 sock->ops 来调用传输层的 listen 操作
 * 	- **SOCK_DGRAM 和 SOCK_RAW 类型不支持 listen**
 * 	- **SOCK_STREAM 类型支持 listen， TCP对应的是** `inet_listen()`
 * 6. `fput_light()`, 根据第二步中获得标志， 对文件的引用计数进行操作
 * 
 * 
 */
/*
 *	Perform a listen. Basically, we allow the protocol to do anything
 *	necessary for a listen, and if that works, we mark the socket as
 *	ready for listening.
 */
SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
	struct socket *sock; // 1
	int err, fput_needed;
	int somaxconn;

	sock = sockfd_lookup_light(fd, &err, &fput_needed); // 2
	if (sock) {
		somaxconn = sock_net(sock->sk)->core.sysctl_somaxconn;
		if ((unsigned)backlog > somaxconn) // 3
			backlog = somaxconn;

		err = security_socket_listen(sock, backlog); // 4
		if (!err)
			err = sock->ops->listen(sock, backlog); // 5

		fput_light(sock->file, fput_needed); // 6
	}
	return err;
}


/*
 *	Move a socket into listening state.
 */
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;

	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}
 


/*inet_csk_listen_start(), 孙小强，2016年11月20日22:39:30
 *
 * 1. `struct inet_sock *inet = inet_sk(sk)`
 * 	`struct inet_connection_sock *icsk = inet_csk(sk)`
 * 2. `reqsk_queue_alloc()`, 为管理连接请求块的散列表分配存储空间(**nr_table_entries**个)，如果分配失败就返回错误
 * 3. 将**连接队列的上限值**（`sk->sk_max_ack_backlog = 0`
 * ） 和 **已经建立连接数**（`sk->sk_ack_backlog = 0`） 清零
 * 4. `inet_csk_delack_init(sk)`, 初始化传输控制块中与演示发送ACK段有关的控制数据结构**icsk_ack**
 * 5. `sk->sk_state = TCP_LISTEN`,  **将传输控制块的状态置为监听状态, TCP_LISTEN**
 * 6. `sk->sk_prot->get_port(sk, inet->num)`,  通过传输控制块和端口号来判断是否绑定端口
 * 	- 如果端口是没有绑定，则进行绑定操作，绑定成功，返回0
 * 	- 如果绑定了，则对绑定的端口进行校验，校验成功，返回0
 * 7. 如果第六步成功
 * 	- 根据端口号(`inet->num`)设置传输控制块中的端口号成员(`inet->sport` 网络字节序)
 * 	- `sk_dst_reset(sk)`, 清空缓存在传输控制块中的目的路有缓存
 * 	- `sk->sk_prot->hash(sk)`，调用hash接口的 inet_hash() 将传输控制块添加到监听散列表中（listening_hash）,完成监听
 * 8. 如果第六步失败，  套接字类型改为 **TCP_CLOSE**, 释放申请到的管理连接请求块的是你列表存储空间
 * 	
 */
int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
	struct inet_sock *inet = inet_sk(sk); //i 1
	struct inet_connection_sock *icsk = inet_csk(sk);
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries); // 2

	if (rc != 0)
		return rc;

	sk->sk_max_ack_backlog = 0; // 3
	sk->sk_ack_backlog = 0;

	inet_csk_delack_init(sk); // 4

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */

	sk->sk_state = TCP_LISTEN; // 5

	if (!sk->sk_prot->get_port(sk, inet->num)) { // 6
		inet->sport = htons(inet->num); // 7

		sk_dst_reset(sk);
		sk->sk_prot->hash(sk);

		return 0;
	}

	sk->sk_state = TCP_CLOSE; // 8
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}


/*sys_accept，孙小强，2016年11月21日20:24:25
 * 1. `sockfd_lookup_light(fd)`,  根据文件描述符 **fd** 获取套接字的指针， 并且返回是否需要对文件引用计数的标志
 * 2. **newsock**，调用 `sock_alloc()` 分配一个新的套接字，用来处理客户端的连接
 * 3. 套接字的类型（`newsock->type`）和 **套接字的系统调用的跳转表**（`newsock->ops`）都有原来的 **sock** 给出
 * 4. `_module_get(newsock->ops->owner)`, 如果`newsock->ops`是以内核模块的方式动态加载，并且注册到内核中的，则需要对内核模块引用计数加一（ ），防止创建过程中此内核模块被动态卸载
 * 5. `sock_alloc_fd(&newfile)`，该函数为 **newsock** 分配一个文件描述符（返回结果为一个新的文件描述符，*newfile 是一个 struct file 结构体变量*）
 * 6. `sock_attach_fd(newsock, newfile)`，将新的套接字与引得文件描述符绑定
 * 7. `security_socket_accept()`，安全模块对套接字的accept做检查
 * 8. `sock->ops->accept()`，是通过套接字的系统调用的跳转表结构体(**sock->ops**)来调用相应的传输协议的accept操作，SOCK_DGRAM 和 SOCK_RAW 类型不支持 accept 接口，只有SOCK_STREAM 类型支持， **TCP 实现的函数为** `inet_accept()`
 * 9. `newsock->ops->getname()`, 如果需要获取客户方套接字的地址， 该操作如果成功就把获得地址拷贝到用户空间参数 **upeer_sockaddr** 指向的变量中，同时还有地址长度
 * 10. `fd_install(newfd, newfile)`,  将获得的文件描述符加入到当前进程已经打开的文件列表中，完成文件与进程的关联
 * 11. `fput_light()`, 根据第二步中获得标志， 对文件的引用计数进行操作,并返回文件描述符
 * 
 */


SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen, int, flags)
{
	struct socket *sock, *newsock;
	struct file *newfile;
	int err, len, newfd, fput_needed;
	struct sockaddr_storage address;

	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	sock = sockfd_lookup_light(fd, &err, &fput_needed); // 1
	if (!sock)
		goto out;

	err = -ENFILE;
	if (!(newsock = sock_alloc()))  // 2
		goto out_put;

	newsock->type = sock->type; // 3
	newsock->ops = sock->ops;

	/*
	 * We don't need try_module_get here, as the listening socket (sock)
	 * has the protocol module (sock->ops->owner) held.
	 */
	__module_get(newsock->ops->owner); // 4

	newfd = sock_alloc_file(newsock, &newfile, flags); // 5  6
	if (unlikely(newfd < 0)) {
		err = newfd;
		sock_release(newsock);
		goto out_put;
	}

	err = security_socket_accept(sock, newsock);  // 7
	if (err)
		goto out_fd;

	err = sock->ops->accept(sock, newsock, sock->file->f_flags); // 8
	if (err < 0)
		goto out_fd;

	if (upeer_sockaddr) {
		if (newsock->ops->getname(newsock, (struct sockaddr *)&address, // 9
					  &len, 2) < 0) {
			err = -ECONNABORTED;
			goto out_fd;
		}
		err = move_addr_to_user((struct sockaddr *)&address, // 9
					len, upeer_sockaddr, upeer_addrlen);
		if (err < 0)
			goto out_fd;
	}

	/* File flags are not inherited via accept() unlike another OSes. */

	fd_install(newfd, newfile); // 10
	err = newfd;

out_put:
	fput_light(sock->file, fput_needed); // 11
out:
	return err;
out_fd:
	fput(newfile);
	put_unused_fd(newfd);
	goto out_put;
}



/*inet_accept(), 孙小强，2016年11月21日20:24:07
 * 
 * 1. 从原来的套接字中获得传输控制块的指针 **sk1**
 * 2. `sk1->sk_prot->accept ( )`,  调用 accept 的传输层接口实现`inet_csk_accept()`来获取**已完成连接（被接受）**的传输控制块（**sk2**），（**三次握手创建一个传输控制块**）
 * 3. `sock_graft(newsock, sk2)`, 用该函数将 newsock 和 sk2 关联起来
 * 4. 将新的套接字的状态(**newsock->state**)修改为 **SS_CONNECTED**
 * 
 */

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */

int inet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk1 = sock->sk; // 1
	int err = -EINVAL;

	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err); // 2

	if (!sk2)
		goto do_err;

	lock_sock(sk2);

	WARN_ON(!((1 << sk2->sk_state) &
		  (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_CLOSE)));

	sock_graft(sk2, newsock);  // 3

	newsock->state = SS_CONNECTED; // 4
	err = 0;
	release_sock(sk2);
do_err:
	return err;
}


/*inet_csk_accept(), 孙小强，2016年11月21日20:23:34
 * 
 * 1. 对套接字的状态进行检查，当前的套接字必须是TCP_LISTEN状态
 * 2. `reqsk_queue_empty(&icsk->icsk_accept_queue)`
 * 		- **icsk**, 连接套接字的结构体类型，其中包含一个**icsk_accept_queue**
 * 		- **icsk_accept_queue**, 该队列中的已接受的成员是在 **tcp_v4_request()**中**inet_csk_reqst_queue_hash_add()** 函数添加进去的
 * 		- 如果该队列为空则表示没有接受到连接，否为接受到了连接
 * 3. 如果没有接受到连接，利用`sock_rcvtimeo()` 函数来获得套接字阻塞时间 **timeo**
 * 	- 如果该套接字是非阻塞的，则直接返回无需睡眠等待
 * 	- 如果该套接字是阻塞的，调用`inet_csk_wait_for_connect(sk, timeo)`，等待**timeo** 时间
 * 4. `reqsk_queue_get_child()`, 此处应该接受到了连接，用该函数从已接受的连接中取出传输控制块（**newsk**）
 * 5. `WARN_ON(newsk->sk_state == TCP_SYN_RECV)`，如果此时的套接字状态是**SYN_RECV** 则会发出警告，因为已经完成了三次握手此时的状态应处于**ESTABLISHED**状态
 * 
 */
/*
 * This will accept the next outstanding connection.
 */
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct sock *newsk;
    int error;

    lock_sock(sk);

    /* We need to make sure that this socket is listening,
     * and that it has something pending.
     */
    error = -EINVAL;
    if (sk->sk_state != TCP_LISTEN) // 1
        goto out_err;

    /* Find already established connection */
    if (reqsk_queue_empty(&icsk->icsk_accept_queue)) {  // 2
        long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK); // 3

        /* If this is a non blocking socket don't sleep */
        error = -EAGAIN;
        if (!timeo)
            goto out_err;

        error = inet_csk_wait_for_connect(sk, timeo); // 3
        if (error)
            goto out_err;
    }

    newsk = reqsk_queue_get_child(&icsk->icsk_accept_queue, sk); // 4
    WARN_ON(newsk->sk_state == TCP_SYN_RECV); // 5
out:
    release_sock(sk);
    return newsk;
out_err:
    newsk = NULL;
    *err = error;
    goto out;
}





/*sys_connect(), 孙小强，2016年11月23日00:36:28
 * 
 * 1. `sockfd_lookup_light(fd)`,  首先根据文件描述符 **fd** 获取套接字的指针（**sock**）， 并且返回是否需要对文件引用计数的标志(**fput_needed**)
 * 2. `move_addr_to_kernel( )`, 将用户空间的套接字地址 **uservaddr** 拷贝到 内核空间(address)
 * 3. 安全模块对套接字接口的 connect 做检查
 * 4.  通过套接字系统调用的跳转表调用对应的传输协议的 connect 操作
 * 		- **TCP:** `inet_stream_connect()`
 * 		- **UDP:** `inet_dgram_connect()`
 * 5. `fput_light()`, 根据第二步中获得标志， 对文件的引用计数进行操作,并返回文件描述符
 * 
 * 
 */

/*
 *	Attempt to connect to a socket with the server address.  The address
 *	is in user space so we verify it is OK and move it to kernel space.
 *
 *	For 1003.1g we need to add clean support for a bind to AF_UNSPEC to
 *	break bindings
 *
 *	NOTE: 1003.1g draft 6.3 is broken with respect to AX.25/NetROM and
 *	other SEQPACKET protocols that take time to connect() as it doesn't
 *	include the -EINPROGRESS status for such sockets.
 */

SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);  // 1
	if (!sock)
		goto out;
	err = move_addr_to_kernel(uservaddr, addrlen, (struct sockaddr *)&address); // 2
	if (err < 0)
		goto out_put;

	err =
	    security_socket_connect(sock, (struct sockaddr *)&address, addrlen); // 3
	if (err)
		goto out_put;

	err = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen, // 4
				 sock->file->f_flags);
out_put:
	fput_light(sock->file, fput_needed); // 5
out:
	return err;
}



/*inet_stream_accept(), 孙小强，2016年11月23日00:33:11
 *
 * 1. 根据 **sock->sk** 得到传输控制块（**sk**）
 * 2. 只有在套接字状态处于 **SS_UNCONNECTED** 状态 并且 传输控制块的状态为 **!TCP_CLOSE** 状态时 才会调用传输控制块上的 connect 接口
 * 		- **TCP:** `tcp_v4_connect(sk, uaddr, addr_len)`
 * 3. connect 成功后将套接字的状态置为 **SS_CONNECTING**
 * 4. `sock_sndtimeo(sk, flags & O_NONBLOCK)`，获取套接字的阻塞时间（**timeo**）
 * 5. 如果传输模块状态是 **TCPF_SYN_SENT** 或者 **TCPF_SYN_RECV** 时
 * 		- **如果套接字是阻塞，等待timeo时间后，释放传输模块再退出**
 * 		- **如果套接字是非阻塞，释放传输模块直接退出**
 * 6. 如果套接字不是以上的状态时， **再次判断传输模块是否为 TCP_CLOSE** ，防止( 中间判断的时候 产生 RST, 超时，ICMP 错误等是的连接关闭 )
 * 7. 将套接字状态修改为 **SS_CONNECTED**成功返回
 *
 */
/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;  // 1
	int err;
	long timeo;

	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;

	lock_sock(sk);

	if (uaddr->sa_family == AF_UNSPEC) {
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED: // 2
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE) // 2
			goto out;

		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;

		sock->state = SS_CONNECTING; // 3

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK); //4

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) { // 5
		/* Error code is set above */
		if (!timeo || !inet_wait_for_connect(sk, timeo)) //5
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE) // 6
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */

	sock->state = SS_CONNECTED; //7
	err = 0;
out:
	release_sock(sk);
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}



/*tcp_v4_connect(), 孙小强, 2016年11月23日00:26:52
 * 
 * 1. 参数有效范围判断
 * 		- **套接字地址长度 应>= 专用套接字的地址长度**
 * 		- **sin_family 应 == AF_INET**
 * 2. 将目标套接字地址转为专用套接字地址，再从中获得 IP地址（**nexthop, daddr**）
 * 3. `ip_route_connect()`，调用该函数根据下一跳地址等信息查找目标路由缓存，如果路由查找命中，则生成一个相应的**路由缓存项(rt)**，缓存项不但可以直接用于当前待发送SYN段，而且还对后续的所有数据包都可以起到加速路由查找的作用
 * 4. TCP 不能使用类型为组播或多播的路由缓存项目
 * 5. 如果没有启用源路由选项 则使用获取到的 **路由选项中的目的地址**(`daddr = rt->rt_dst`)
 * 6. 如果客户端没有本方在 connect 前没有指明套接字的IP地址（`inet->inet_saddr` 为空），就会在这里设置
 * 		-  `inet->inet_saddr = rt->rt_src;` **源地址**
 * 		-  `inet->inet_rcv_saddr = inet->inet_saddr;` **本方接收地址**
 * 7. 如果传输控制块中的时间戳 和 目的地址已经被使用过，则说明传输控制块已经建立过连接并进行过通讯，则需重新初始化它们
 * 8. 给传输控制块初始化 对端端口 和 地址
 * 9. 将TCP 状态设置为 **SYN_SEND** ，动态绑定一个本地端口，并将传输控制块添加到散列表中，由于在动态分配端口时，如果找到的是已经使用过端口，则需要在TIME_WAIT状态中进行相应的确认，因此调用 `inet_hash_connect()` 时需要TIMEWAIT传输控制块和参数管理器**tcp_death_row**作为参数
 * 10. `ip_route_newports()`，在路由表中重新缓存表中重新设置本地端口到目标端口的映射关系
 * 11. 根据传输控制块的路由输出设置特性 来设置 传输控制块中的路由网络设备的特性
 * 12. `secure_tcp_sequence_number()`，如果**write_seq**字段值为零，则说明传输控制块还没有设置初始序号，因此需要根据双发的地址端口计算初始序列号，同时根据发送需要 和当前时间得到用于设置IP首部ID域的值
 * 13. `tcp_connect(sk)`，构造并发送 SYN 段
 * 
 */
/* This will initiate an outgoing connection. */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	__be32 daddr, nexthop;
	int tmp;
	int err;

	if (addr_len < sizeof(struct sockaddr_in)) // 1
		return -EINVAL;

	if (usin->sin_family != AF_INET) // 1
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr; // 2
	if (inet->opt && inet->opt->srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}


	tmp = ip_route_connect(&rt, nexthop, inet->inet_saddr, // 3
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->inet_sport, usin->sin_port, sk, 1);
	if (tmp < 0) { 
		if (tmp == -ENETUNREACH)
			IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return tmp;
	}


	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) { // 4
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet->opt || !inet->opt->srr) // 5
		daddr = rt->rt_dst;

	if (!inet->inet_saddr) // 6
		inet->inet_saddr = rt->rt_src;
	inet->inet_rcv_saddr = inet->inet_saddr;

	if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) { // 7
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer(rt);
		/*
		 * VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state
		 * TIME-WAIT * and initialize rx_opt.ts_recent from it,
		 * when trying new connection.
		 */
		if (peer != NULL &&
		    (u32)get_seconds() - peer->tcp_ts_stamp <= TCP_PAWS_MSL) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	inet->inet_dport = usin->sin_port; // 8
	inet->inet_daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet->opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;

	tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	
	tcp_set_state(sk, TCP_SYN_SENT); // 9
	err = inet_hash_connect(&tcp_death_row, sk); // 9
	if (err)
		goto failure;

	err = ip_route_newports(&rt, IPPROTO_TCP, // 10
				inet->inet_sport, inet->inet_dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */

	sk->sk_gso_type = SKB_GSO_TCPV4; // 11
	sk_setup_caps(sk, &rt->u.dst); // 11


	if (!tp->write_seq)
		tp->write_seq = secure_tcp_sequence_number(inet->inet_saddr, // 12
							   inet->inet_daddr,
							   inet->inet_sport,
							   usin->sin_port);

	inet->inet_id = tp->write_seq ^ jiffies;


	err = tcp_connect(sk); // 13
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}


