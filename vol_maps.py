'''
Lots of this is taken directly from volatility. It's an integration.
'''

from panda import Panda, blocking
from sys import argv
from time import time
from vol_lib import volatility_symbols
from volatility.framework.objects import utility
import pdb

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch,qcow=qcow,extra_args=extra,mem="1G")

timechange = 5
oldtime = time()

@panda.cb_asid_changed()
def on_asid_change(env, old_asid, new_asid):
	global oldtime, timechange
	if time() - oldtime > timechange:
		vmlinux = volatility_symbols(panda)
		init_task = vmlinux.object_from_symbol(symbol_name = "init_task")
		print("PID\tProcess\tStart\tEnd\tFlags\tPgOff\tMajor\tMinor\tInode\tFile Path")
		tasks = [task for task in init_task.tasks if task.pid]
		for task in tasks:
			if not task.mm:
				continue
		
			name = utility.array_to_string(task.comm)
		
			for vma in task.mm.get_mmap_iter():
				flags = vma.get_protection()
				page_offset = vma.get_page_offset()
				major = 0
				minor = 0
				inode = 0
				
				if vma.vm_file != 0:
				    dentry = vma.vm_file.get_dentry()
				    if dentry != 0:
				        inode_object = dentry.d_inode
				        major = inode_object.i_sb.major
				        minor = inode_object.i_sb.minor
				        inode = inode_object.i_ino
				
				path = vma.get_name(vmlinux.context, task)
		
				print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(task.pid, name, hex(vma.vm_start), hex(vma.vm_end), flags, hex(page_offset), major, minor, inode, path))
					


		oldtime = time()
		timechange = 15
	return 0

@blocking
def init():
	panda.revert("cmdline")


panda.queue_async(init)
panda.run()
