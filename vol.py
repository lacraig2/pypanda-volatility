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

total_time, number_runs = 0,0 

@panda.cb_asid_changed()
def on_asid_change(env, old_asid, new_asid):
	global oldtime, timechange, total_time, number_runs
	if time() - oldtime > timechange:
		a = time()
		vmlinux = volatility_symbols(panda)
		init_task = vmlinux.object_from_symbol(symbol_name = "init_task")
		out = [(task.pid,task.parent.pid,utility.array_to_string(task.comm)) for task in init_task.tasks if task.pid]
		ran_in = time() - a
		total_time += ran_in
		number_runs += 1
		print("ran in "+str(ran_in) +" seconds")
		print("average of "+str(total_time/number_runs) +" for "+str(number_runs))
		print(out)
		print(len(out))
		pdb.set_trace()
		oldtime = time()
		timechange = 15
	return 0

@blocking
def init():
	panda.revert("cmdline")


panda.queue_async(init)
panda.run()
