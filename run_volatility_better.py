# This file is largely a copy of the volatility __init__.py for its command line

import logging, pdb
from sys import argv
from panda import Panda, blocking
from time import time
from urllib.request import BaseHandler, pathname2url
import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import MuteProgress
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, renderers, configuration
from volatility.framework.automagic import linux
from volatility.framework.layers.linear import LinearlyMappedLayer
from volatility.framework.objects import utility

class PandaFile(object):
	def __init__(self,length):
		self.pos = 0
		self.length = length
		self.closed = False
		self.mode = "rb"
		self.name = "/tmp/panda.panda"

	def readable(self):
		return self.closed

	def read(self, size=1):
		data = panda.physical_memory_read(self.pos,size)
		self.pos += size
		return data
	
	def peek(self, size=1):
		return panda.physical_memory_read(self.pos, size)

	def seek(self, pos, whence=0):
		if whence == 0:
			self.pos = pos
		elif whence == 1:
			self.pos += pos
		else:
			self.pos = self.length - pos

	def tell(self):
		return self.pos

	def close(self):
		self.closed = True
	

class FileHandler(BaseHandler):
	def default_open(self, req):
		if 'panda.panda' in req.full_url:
			length = panda.libpanda.ram_size
			if length > 0xc0000000:
				length += 0x40000000
			return PandaFile(length=length)
		else:
			return None
	def file_close(self):
		return True



class CommandLine(interfaces.plugins.FileConsumerInterface):
	"""Constructs a command-line interface object for users to run plugins."""

	def __init__(self):
		self.output_dir = None

	def run(self):
		# we aren't really doing logging, but you can change these numbers to get more details
		vollog = logging.getLogger(__name__)
		vollog = logging.getLogger()
		vollog.setLevel(1000)
		console = logging.StreamHandler()
		console.setLevel(logging.WARNING)
		formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
		console.setFormatter(formatter)
		vollog.addHandler(console)
		volatility.framework.require_interface_version(1, 0, 0)
		# also change here for log level
		console.setLevel(1000)
		constants.PARALLELISM = constants.Parallelism.Off
		ctx = contexts.Context()  # Construct a blank context
		failures = framework.import_files(volatility.plugins,
										  True)  # Will not log as console's default level is WARNING
		automagics = automagic.available(ctx)
		plugin_list = framework.list_plugins()
		seen_automagics = set()
		configurables_list = {}
		for amagic in automagics:
			if amagic in seen_automagics:
				continue
			seen_automagics.add(amagic)
			if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
				configurables_list[amagic.__class__.__name__] = amagic

		plugin_name = "linux.pstree.PsTree" # we're just "kinda" running a plugin
		plugin = plugin_list[plugin_name]
		base_config_path = "plugins"
		plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)

		# It should be up to the UI to determine which automagics to run, so this is before BACK TO THE FRAMEWORK
		automagics = automagic.choose_automagic(automagics, plugin)
		single_location = "file:" + pathname2url("/panda.panda") # this is our fake file that represents QEMU memory
		ctx.config['automagic.LayerStacker.single_location'] = single_location
		constructed = plugins.construct_plugin(ctx, automagics, plugin, base_config_path, MuteProgress(), self)
		return constructed

_vmlinux = None

def give_vmlinux():
	global _vmlinux
	if not _vmlinux:
		constructed_original = CommandLine().run()
		linux.LinuxUtilities.aslr_mask_symbol_table(constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'])
		_vmlinux = contexts.Module(constructed_original.context, constructed_original.config['vmlinux'],constructed_original.config['primary'], 0)
	else:
		LinearlyMappedLayer.read.cache_clear()		
	return _vmlinux

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
		vmlinux = give_vmlinux()
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

