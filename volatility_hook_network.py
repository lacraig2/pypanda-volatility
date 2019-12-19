'''
Lots of this is taken directly from volatility. It's an integration.
'''

from panda import Panda, blocking
from sys import argv
from time import time
from vol_lib import volatility_symbols
from volatility.framework.objects.utility import array_to_string as a2s
import pdb

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch="x86_64", qcow=qcow,extra_args=extra,mem="1G")

oldtime = time()
timechange = 1

@panda.cb_asid_changed()
def setup_hooks(env, old_asid, new_asid):
	global oldtime, timechange
	if time() - oldtime > timechange:
		vmlinux = volatility_symbols(panda)
		init_task = vmlinux.object_from_symbol(symbol_name = "init_task")
		ip_rcv = vmlinux.object_from_symbol(symbol_name = "ip_local_deliver_finish")
		
		# must adjust pointer between volatility and PANDA
		offset = ip_rcv._vol["offset"] | 0xffff000000000000

		#static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
		@panda.hook(offset)
		def hook_ip_rcv_finish(env, tb):
			# RDI, RSI, RDX, R10, R8 and R9
			vmlinux = volatility_symbols(panda)
			regs = env.env_ptr.regs
			rdi, rsi, rdx, r10, r8, r9 = regs[7], regs[6], regs[2], regs[10], regs[8], regs[9]
			net = vmlinux.object(object_type = "net", offset = rdi)
			sk = vmlinux.object(object_type = "sock", offset = rsi)
			skb = vmlinux.object(object_type = "sk_buff", offset = rdx)
			print("interface "+a2s(skb.dev.name)+ " receiving packet of size "+ str(skb.len))
			#if it has data
			if skb.len > 44:
				# read the data
				layer = vmlinux.context.layers._layers["primary"]
				packet_content = layer.read(skb.data+40,skb.len-40).decode(errors='ignore')
				print("Content sent: " +packet_content)
			return 0
		timechange = 100000000
		oldtime = time()
	return 0

@blocking
def init():
	panda.revert("cmdline")

panda.queue_async(init)
panda.run()
