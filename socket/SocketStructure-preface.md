---
title: 套接字层的基本数据结构
date: 2016-11-30 19:35:03
tags: 套接字
---

	套接字层的基本数据结构
	
1. 套接字层位于应用程序与协议栈之间
2. 对应用程序屏蔽了与协议相关实现的具体细节
3. 将应用程序发送的与协议无关的请求映射到与协议相关的实现
4. 不同协议都对应一个 proto_ops 结构，这个结构实现了套接字层函数到传输层函数的映射
5. 套接字层将一般的请求转换为指定的协议操作

![](/images/1.1_1.png)

	具体数据结构的讲解

- [socket 结构体](http://sunxiaoqiang.top/2016/11/30/SocketStructure-2/)
- [proto_ops 结构体](http://sunxiaoqiang.top/2016/11/30/SocketStructure-3/)

