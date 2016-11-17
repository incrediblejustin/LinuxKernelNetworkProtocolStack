[TOC]
##系统调用入口

进程与内核交互是通过一组定义好的函数函数来进行的，这些函数成为系统调用。

###系统调用机制（linux在i386上的实现）

- 每一个系统调用均被编号， 成为系统调用号
- 当进程进行一个系统调用时， 要通过终端指令 **INT 80H**, 从用户空间进入内核空间，并将系统调用号作为参数传递给内核函数
- 在 linux 系统中所有的系统调用都会进入系统的同一个地址， 这个地址称为 **system_call**
- 最终根据系统调用号， 调用系统调用表 **sys_call_table** 中的某一个函数


###套接字的系统调用

- 建立
	- socket:	 	在指明的通信域内产生一个 未命名 的套接字
	- bind:		 	分配一个本地地址给套接字
- 服务器 	
	- liste:	 	套接字准备接收连接请求
	- accept:	 	等待接受连接
- 客户 	
	- connect: 	 	同外部套接字建立连接
- 输入 	
	- read:		 	接收数据到一个缓冲区
	- readv: 	 	接收数据到多个缓冲区
	- recv: 	 	指明选项接收数据
	- recvfrom:  	接收数据和发送者的地址
	- redvmsg:	 	接收数据到多个缓存中, 接收控制信息和发送者地址;指明接收选项
- 输出 	
	- write:	 	发送一个缓冲区的数据
	- writev:	 	发送多个缓冲区的数据
	- send:		 	指明选项发送数据
	- secdto:	 	发送数据到指明的地址
	- sendmsg:	 	从多个缓存发送数据和控制信息到指明的地址; 指明发送选项
- I/O: 	
	- select: 	 	等待 I/O 事件
- 终止 	
	- shutdown:  	终止一个或者连个方向上的连接
	- close: 	 	终止连接并释放套接字
- 管理 	
	- fcntl: 	 	修改 I/O 语义
	- ioctl:	 	各类套接字的操作
	- setsockopt:	设置套接字或者协议选项
	- getsockopt:	获得套接字或者协议选项
	- getsockname:	得到分配给套接字的本地地址
	- getpeername:	得到分配给套接字的远端地址


###socket系统调用号

系统中所有的 socket 系统调用总入口为 **sys_socketcall()**有连个参数

- call
**操作码**，函数中通过操作码跳转到真正的系统调用函数
![7.1_2](./pic/7.1_3.png)

- *args
**指向一个数组的指针 **，指向用户空间，表示系统调用的参数

- nas[call] 
**表示需要从用户空间拷贝的数据长度**
```
/* Argument list sizes for compat_sys_socketcall */
#define AL(x) ((x) * sizeof(u32))
static unsigned char nas[20] =
{
	AL(0),AL(3),AL(3),AL(3),AL(2),
	AL(3),AL(3),AL(3),AL(4),AL(4),
	AL(4),AL(6),AL(6),AL(2),AL(5),
	AL(5),AL(3),AL(3),AL(4),AL(5)
};
#undef AL
```

- 代码注释
```
asmlinkage long compat_sys_socketcall(int call, u32 __user *args)
{
	int ret;
	u32 a[6];
	u32 a0, a1;

	if (call < SYS_SOCKET || call > SYS_RECVMMSG)
		return -EINVAL;
	//将args指向的用户空间的nas[call]个参数拷贝进内核空间中
	if (copy_from_user(a, args, nas[call]))
		return -EFAULT;
	a0 = a[0];
	a1 = a[1];
	//根据系统调用号的不同来调用真正的系统调用
	//不同的系统调用在下面介绍
	switch (call) {
	case SYS_SOCKET:
		ret = sys_socket(a0, a1, a[2]);
		break;
	case SYS_BIND:
		ret = sys_bind(a0, compat_ptr(a1), a[2]);
		break;
	case SYS_CONNECT:
		ret = sys_connect(a0, compat_ptr(a1), a[2]);
		break;
	case SYS_LISTEN:
		ret = sys_listen(a0, a1);
		break;
	//省略一些系统调用...
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

```

- 常见系统调用流程图
![7.1_3](./pic/7.1_3.png)

