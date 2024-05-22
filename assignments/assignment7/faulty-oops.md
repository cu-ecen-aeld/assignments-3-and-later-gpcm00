# OOPS
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x0000000096000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045, ISS2 = 0x00000000
  CM = 0, WnR = 1, TnD = 0, TagAccess = 0
  GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
user pgtable: 4k pages, 39-bit VAs, pgdp=0000000041b61000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 0000000096000045 [#1] SMP
Modules linked in: faulty(O) scull(O) [last unloaded: faulty(O)]
CPU: 0 PID: 162 Comm: sh Tainted: G           O       6.6.18 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x8/0x10 [faulty]
lr : vfs_write+0xc4/0x39c
sp : ffffffc080e83d20
x29: ffffffc080e83d20 x28: ffffff8001b34f80 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 000000000000000c x22: 000000000000000c x21: ffffffc080e83df0
x20: 0000005581685b30 x19: ffffff8001bb3300 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000000 x4 : ffffffc078c59000 x3 : ffffffc080e83df0
x2 : 000000000000000c x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x8/0x10 [faulty]
 ksys_write+0x70/0x104
 __arm64_sys_write+0x1c/0x28
 invoke_syscall+0x54/0x124
 el0_svc_common.constprop.0+0x40/0xe0
 do_el0_svc+0x1c/0x28
 el0_svc+0x40/0xe8
 el0t_64_sync_handler+0x100/0x12c
 el0t_64_sync+0x190/0x194
Code: ???????? ???????? d2800001 d2800000 (b900003f) 
---[ end trace 0000000000000000 ]---

# Analysis
The first message actually tell us what is the problem that crashed the system: "Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000"
Then, we can analyze the functions currently on the stack to trace the problem. We can see the funtion faulty_write at the button of the stack, which gives us a hint of where the problem is.
Finally, we can also see that the program counter is currently pointing to faulty_write.

