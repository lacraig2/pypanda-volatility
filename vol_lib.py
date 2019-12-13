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

	
'''
Constructs a file and file handler that volatility can't ignore to back by PANDA physical memory
'''
def make_panda_file_handler(panda):
	class PandaFile(object):
		def __init__(self,length, panda):
			self.pos = 0
			self.length = length
			self.closed = False
			self.mode = "rb"
			self.name = "/tmp/panda.panda"
			self.panda = panda
	
		def readable(self):
			return self.closed
	
		def read(self, size=1):
			data = self.panda.physical_memory_read(self.pos,size)
			self.pos += size
			return data
		
		def peek(self, size=1):
			return self.panda.physical_memory_read(self.pos, size)
	
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

	class PandaFileHandler(BaseHandler):
		def default_open(self, req):
			if 'panda.panda' in req.full_url:
				length = panda.libpanda.ram_size
				if length > 0xc0000000:
					length += 0x40000000
				return PandaFile(length=length, panda=panda)
			else:
				return None
		def file_close(self):
			return True
	
	globals()["PandaFileHandler"] = PandaFileHandler
	


'''
We are faking running this from the command line and running this programmatically.

Why? Because it's easier to do it this way than ask the people at volatility to modify
their project.
'''
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

def volatility_symbols(panda):
	global _vmlinux
	if not _vmlinux:
		make_panda_file_handler(panda)
		constructed_original = CommandLine().run()
		linux.LinuxUtilities.aslr_mask_symbol_table(constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'])
		_vmlinux = contexts.Module(constructed_original.context, constructed_original.config['vmlinux'],constructed_original.config['primary'], 0)
	else:
		LinearlyMappedLayer.read.cache_clear()		
	return _vmlinux


