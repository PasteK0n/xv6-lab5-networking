#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "net.h"
#include "e1000_dev.h"

#define TX_RING_SIZE 16
static struct tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
static struct mbuf *tx_mbufs[TX_RING_SIZE];

#define RX_RING_SIZE 16
static struct rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
static struct mbuf *rx_mbufs[RX_RING_SIZE];

// remember where the e1000's registers live.
static volatile uint32 *regs;

struct spinlock e1000_lock;

// called by pci_init().
// xregs is the memory address at which the
// e1000's registers are mapped.
void
e1000_init(uint32 *xregs)
{
  int i;

  initlock(&e1000_lock, "e1000");

  regs = xregs;

  // Reset the device
  regs[E1000_IMS] = 0; // disable interrupts
  regs[E1000_CTL] |= E1000_CTL_RST;
  regs[E1000_IMS] = 0; // redisable interrupts
  __sync_synchronize();

  // [E1000 14.5] Transmit initialization
  memset(tx_ring, 0, sizeof(tx_ring));
  for (i = 0; i < TX_RING_SIZE; i++) {
    tx_ring[i].status = E1000_TXD_STAT_DD;
    tx_mbufs[i] = 0;
  }
  regs[E1000_TDBAL] = (uint64) tx_ring;
  if(sizeof(tx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_TDLEN] = sizeof(tx_ring);
  regs[E1000_TDH] = regs[E1000_TDT] = 0;
  
  // [E1000 14.4] Receive initialization
  memset(rx_ring, 0, sizeof(rx_ring));
  for (i = 0; i < RX_RING_SIZE; i++) {
    rx_mbufs[i] = mbufalloc(0);
    if (!rx_mbufs[i])
      panic("e1000");
    rx_ring[i].addr = (uint64) rx_mbufs[i]->head;
  }
  regs[E1000_RDBAL] = (uint64) rx_ring;
  if(sizeof(rx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_RDH] = 0;
  regs[E1000_RDT] = RX_RING_SIZE - 1;
  regs[E1000_RDLEN] = sizeof(rx_ring);

  // filter by qemu's MAC address, 52:54:00:12:34:56
  regs[E1000_RA] = 0x12005452;
  regs[E1000_RA+1] = 0x5634 | (1<<31);
  // multicast table
  for (int i = 0; i < 4096/32; i++)
    regs[E1000_MTA + i] = 0;

  // transmitter control bits.
  regs[E1000_TCTL] = E1000_TCTL_EN |  // enable
    E1000_TCTL_PSP |                  // pad short packets
    (0x10 << E1000_TCTL_CT_SHIFT) |   // collision stuff
    (0x40 << E1000_TCTL_COLD_SHIFT);
  regs[E1000_TIPG] = 10 | (8<<10) | (6<<20); // inter-pkt gap

  // receiver control bits.
  regs[E1000_RCTL] = E1000_RCTL_EN | // enable receiver
    E1000_RCTL_BAM |                 // enable broadcast
    E1000_RCTL_SZ_2048 |             // 2048-byte rx buffers
    E1000_RCTL_SECRC;                // strip CRC
  
  // ask e1000 for receive interrupts.
  regs[E1000_RDTR] = 0; // interrupt after every received packet (no timer)
  regs[E1000_RADV] = 0; // interrupt after every packet (no timer)
  regs[E1000_IMS] = (1 << 7); // RXDW -- Receiver Descriptor Write Back
}

int
e1000_transmit(struct mbuf *m)
{
  uint32 tail;
  struct tx_desc *desc;

  acquire(&e1000_lock);
  tail = regs[E1000_TDT];
  desc = &tx_ring[tail];

  // 1. 必须检查 DD 位：确认网卡已经处理完了这个槽位的旧包
  if (!(desc->status & E1000_TXD_STAT_DD)) {
    release(&e1000_lock);
    return -1; // 环形队列满了，不能覆盖，返回 -1 让 sys_send 释放当前的 m
  }

  // 2. 安全释放：只有 DD 置位了，tx_mbufs[tail] 里的旧包才真正发完了
  if (tx_mbufs[tail]) {
    mbuffree(tx_mbufs[tail]);
    tx_mbufs[tail] = 0;
  }

  // 3. 填充新包信息
  desc->addr = (uint64)m->head;
  desc->length = m->len;
  desc->status = 0; // 重置状态位，等待网卡下次设置 DD
  desc->cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS; // EOP: 包结束; RS: 要求设置 DD

  // 4. 保存引用以供将来释放
  tx_mbufs[tail] = m;

  __sync_synchronize(); // 屏障：确保内存写入完成后再更新寄存器

  // 5. 更新 TDT
  regs[E1000_TDT] = (tail + 1) % TX_RING_SIZE;
  
  release(&e1000_lock);
  return 0;
}


static void
e1000_recv(void)
{
  while (1) {
    // 1. 获取下一个待处理的索引 (RDT + 1)
    uint32 rx_index = (regs[E1000_RDT] + 1) % RX_RING_SIZE;
    
    // 2. 检查 DD 位
    if (!(rx_ring[rx_index].status & E1000_RXD_STAT_DD)) {
      break; // 没有新包，退出循环
    }

    // 3. 提取收到的 mbuf 并设置长度
    struct mbuf *m = rx_mbufs[rx_index];
    m->len = rx_ring[rx_index].length;

    // 4. 关键：为下一次接收分配新的 mbuf 替换当前槽位
    // 只有这样，原有的 m 才能安全地在协议栈中流动而不被硬件干扰
    struct mbuf *new_m = mbufalloc(0);
    if (new_m == 0) {
      // 如果分配失败，为了防止硬件卡死，通常选择丢弃当前包并重用旧 mbuf
      rx_ring[rx_index].status = 0;
      regs[E1000_RDT] = rx_index;
      continue;
    }

    rx_mbufs[rx_index] = new_m;
    rx_ring[rx_index].addr = (uint64)new_m->head;
    rx_ring[rx_index].status = 0; // 必须手动清零状态位

    // 5. 更新 RDT 后再提交给协议栈，保证硬件进度同步
    regs[E1000_RDT] = rx_index;

    // 6. 提交给协议栈
    net_rx(m); 
  }
}



void
e1000_intr(void)
{
  // tell the e1000 we've seen this interrupt;
  // without this the e1000 won't raise any
  // further interrupts.
  regs[E1000_ICR] = 0xffffffff;

  e1000_recv();
}
