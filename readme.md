##源码阅读日志

### day 1, 2016年11月18日00:46:05
	增加了./socket/readme.md
	准备将readme.md作为笔记，记录linux内核网络协议栈源码剖析的过程
### day 2, 2016年11月18日20:24:07
	增加了对`sys_socket(), sock_create, __sock_create(), inet_create()`的完全注释
	socket的创建过程已经完成，接下来就要对绑定函数完成剖析
### day 3, 2016年11月19日23:57:15
	完成了sys_bind(), inet_bind() 的完全注释
### day 4, 2016年11月20日22:43:03
	sys_listen(), inet_listen(), inet_csk_listen_start(),都已经完成
	记下来就是 accept 系统调用