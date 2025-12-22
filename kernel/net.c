#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x02 };

static struct spinlock netlock;

// 分配一个新的 mbuf
struct mbuf *
mbufalloc(int headroom) {
  struct mbuf *m = kalloc(); // 分配物理页 [cite: 76, 94]
  if (m == 0) return 0;
  
  m->next = 0;
  m->head = (char *)m->buf + headroom; // 预留 headroom 空间给协议头 [cite: 43]
  m->len = 0;
  return m;
}

// 释放 mbuf
void
mbuffree(struct mbuf *m) {
  kfree(m); // 将内存还给内核堆 [cite: 46, 56, 133]
}

// 向前移动 head，为添加协议头腾出空间 (用于发送)
char *
mbufpush(struct mbuf *m, unsigned int len) {
  m->head -= len;
  m->len += len;
  return m->head;
}

// 向后移动 head，剥离已处理的协议头 (用于接收)
char *
mbufpull(struct mbuf *m, unsigned int len) {
  char *tmp = m->head;
  m->head += len;
  m->len -= len;
  return tmp;
}

// 在末尾增加数据长度
char *
mbufput(struct mbuf *m, unsigned int len) {
  char *p = m->head + m->len;
  m->len += len;
  return p;
}

// 插入队列尾部
void
mbufq_pushtail(struct mbufq *q, struct mbuf *m) {
  m->next = 0;
  if (!q->head) {
    q->head = q->tail = m;
  } else {
    q->tail->next = m;
    q->tail = m;
  }
}

// 从队列头部取出
struct mbuf *
mbufq_pophead(struct mbufq *q) {
  if (!q->head) return 0;
  struct mbuf *m = q->head;
  q->head = m->next;
  return m;
}

struct sock {
  struct spinlock lock;       // 保护该 socket 的并发访问
  uint32 raddr;               // 远程 IP 地址（可选，多用于已连接的 socket）
  uint16 lport;               // 本地绑定的端口号
  uint16 rport;               // 远程端口号
  struct mbufq rxq;           // 接收缓冲区队列，存放等待读取的 mbuf
};

struct socket_table{
  struct spinlock lock;       // 保护 sockets 数组分配的全局锁
  struct sock sock[NSOCK];
} ;

struct socket_table socket_table;

void
sockinit(void)
{
  initlock(&socket_table.lock, "socket_table");
  for(int i = 0; i < NSOCK; i++){
    struct sock *s = &socket_table.sock[i];
    initlock(&s->lock, "sock");
    
    s->rxq.head = 0;
    s->rxq.tail = 0;
    
    s->lport = 0; // 0 表示该槽位空闲
    s->raddr = 0;
    s->rport = 0;
  }
}

struct sock*
sockalloc(uint16 lport)
{
  struct sock *s;

  acquire(&socket_table.lock);
  for(s = socket_table.sock; s < &socket_table.sock[NSOCK]; s++){
    acquire(&s->lock);
    if(s->lport == 0){ // 找到空闲槽位
      s->lport = lport;
      
      // 适配你的 mbuf 队列逻辑
      s->rxq.head = 0; // 确保队列头部为空
      s->rxq.tail = 0; // 确保队列尾部为空
      
      struct mbuf *m;
      while((m = mbufq_pophead(&s->rxq)) != 0){
        mbuffree(m);
      }

      // 初始化远程信息
      s->raddr = 0;
      s->rport = 0;

      release(&s->lock);
      release(&socket_table.lock);
      return s;
    }
    release(&s->lock);
  }
  release(&socket_table.lock);
  return 0;
}

void
netinit(void)
{
  initlock(&netlock, "netlock");
}


//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  //
  // Your code here.
  //
  int lport;
  struct sock *s;

  // 1. 获取用户传入的本地端口参数
  argint(0, &lport);

  // 2. 分配并初始化一个 socket 结构
  // 我们在第一阶段实现的 sockalloc 会处理全局表的查找与锁定
  s = sockalloc(lport);
  if (s == 0)
    return -1;

  // 3. 将 socket 指针关联到当前进程的文件描述符表或特定的内核变量中
  // 在实验框架中，通常直接返回 0 表示成功，后续 recv 会根据端口匹配
  return 0;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  //
  // Optional: Your code here.
  //

  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  uint64 src_ip_addr, sport_addr, buf_addr;
  int dport, maxlen;
  struct mbuf *m;
  struct sock *s = 0;
  struct proc *p = myproc();

  argint(0, &dport);
  argaddr(1, &src_ip_addr);
  argaddr(2, &sport_addr);
  argaddr(3, &buf_addr);
  argint(4, &maxlen);

  acquire(&socket_table.lock);
  for (int i = 0; i < NSOCK; i++) {
    if (socket_table.sock[i].lport == dport) {
      s = &socket_table.sock[i];
      acquire(&s->lock);
      break;
    }
  }
  release(&socket_table.lock);

  if (s == 0) return -1;

  while (s->rxq.head == 0) {
    if (p->killed) { release(&s->lock); return -1; }
    sleep(&s->rxq, &s->lock);
  }

  m = mbufq_pophead(&s->rxq);

  uint32 sip = htonl(s->raddr);
  uint16 sport=s->rport;

  
  // 拷贝源信息 (此时 s->lock 仍持有，保护 raddr/rport)
  if (copyout(p->pagetable, src_ip_addr, (char *)&sip, 4) < 0 ||
      copyout(p->pagetable, sport_addr, (char *)&sport, 2) < 0) {
    mbuffree(m);
    release(&s->lock);
    return -1;
  }
  release(&s->lock);

  int count = m->len;
  if (count > maxlen) count = maxlen;

  if (copyout(p->pagetable, buf_addr, m->head, count) < 0) {
    mbuffree(m);
    return -1;
  }

  mbuffree(m); // 释放读取完的 mbuf
  return count;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  if (len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp) > MBUF_SIZE)return -1;
  struct mbuf *m = mbufalloc(sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp));
  if (m == 0)
  {
    printf("sys_send: mbufalloc failed\n");
    return -1;
  }

  char *payload = mbufput(m, len);
  if (copyin(p->pagetable, payload, bufaddr, len) < 0) {
    printf("sys_send: copy failed\n");
    mbuffree(m);
    return -1;
  }

  struct udp *udp = (struct udp *)mbufpush(m, sizeof(struct udp));
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));
  udp->sum = 0;

  struct ip *ip = (struct ip *)mbufpush(m, sizeof(struct ip));
  ip->ip_vhl = 0x45;
  ip->ip_tos = 0;
  ip->ip_len = htons(m->len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = 0;
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));
  
  struct eth *eth = (struct eth *)mbufpush(m, sizeof(struct eth));
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);


  if (e1000_transmit(m) < 0) {
    mbuffree(m);
    return -1;
  }

  return 0;
}

void
udp_rx(struct mbuf *m, uint32 src_ip)
{
  struct udp *udp = (struct udp *) m->head;
  uint16 ulen = ntohs(udp->ulen);
  if (ulen < sizeof(struct udp) || ulen > m->len) {
    mbuffree(m);
    return;
  }
  m->len = ulen;

  uint16 dport = ntohs(udp->dport);
  uint16 sport = ntohs(udp->sport);

  struct sock *s = 0;
  acquire(&socket_table.lock);
  for (int i = 0; i < NSOCK; i++) {
    if (socket_table.sock[i].lport == dport) {
      s = &socket_table.sock[i];
      acquire(&s->lock);
      break; 
    }
  }
  release(&socket_table.lock);

  if (s) {
    // --- 修改1: 限制队列长度 (解决 ping3 报错) ---
    int count = 0;
    for (struct mbuf *q = s->rxq.head; q; q = q->next) count++;
    if (count >= 10) {
      release(&s->lock);
      mbuffree(m);
      return;
    }

    // --- 修改2: 记录信息 ---
    s->raddr = src_ip; 
    s->rport = sport;
    
    mbufpull(m, sizeof(struct udp));
    mbufq_pushtail(&s->rxq, m);
    
    wakeup(&s->rxq);
    release(&s->lock);
  } else {
    mbuffree(m);
  }
}

void
ip_rx(struct mbuf* m)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  //
  // Your code here.
  //
  struct ip *ip = (struct ip *)m->head;
  if (m->len < sizeof(struct ip) || ip->ip_vhl != 0x45) {
    mbuffree(m);
    return;
  }

  if (ip->ip_p == IPPROTO_UDP) {
    uint32 src_ip = ip->ip_src;

    if (mbufpull(m, sizeof(struct ip)) == 0) {
      mbuffree(m);
      return;
    }
    udp_rx(m, src_ip);
  }else{
    mbuffree(m);
  }
}


//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(struct mbuf *m)
{
  static int seen_arp = 0;

  if(seen_arp){
    mbuffree(m);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct arp *inarp = (struct arp *) m->head;
  struct eth *ineth = (struct eth *) ((char*)inarp - sizeof(struct eth));

  struct mbuf *m_reply = mbufalloc(sizeof(struct eth) + sizeof(struct arp));
  if(m_reply == 0) {
    mbuffree(m);
    return;
  }

  struct arp *arp = (struct arp *) mbufput(m_reply, sizeof(struct arp));
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  struct eth *eth = (struct eth *) mbufpush(m_reply, sizeof(struct eth));
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_ARP);

  e1000_transmit(m_reply);

  mbuffree(m);
}

void
net_rx(struct mbuf *m)
{
  if (m->len < sizeof(struct eth)) {
    mbuffree(m);
    return;
  }

  struct eth *eth = (struct eth *) mbufpull(m, sizeof(struct eth));

  if(ntohs(eth->type) == ETHTYPE_ARP){
    if (m->len >= sizeof(struct arp))
      arp_rx(m);
    else
      mbuffree(m);
  } else if(ntohs(eth->type) == ETHTYPE_IP){
    if (m->len >= sizeof(struct ip))
      ip_rx(m);
    else
      mbuffree(m);
  } else {
    mbuffree(m);
  }
}
