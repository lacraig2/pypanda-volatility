# This file is largely a copy of the volatility __init__.py for its command line

import time
import pdb
from sys import argv
from panda import Panda, blocking
import argparse
import shlex
import inspect
import json
import logging
import os
import sys
from typing import Any, Dict, Type, Union
from urllib import parse, request

import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli import text_renderer
from volatility.framework import renderers
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
from volatility.framework.configuration import requirements
from volatility.framework.layers.linear import LinearlyMappedLayer

from typing import Callable, Iterable, List, Any

from volatility.framework import renderers, interfaces, contexts
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
#arch = "i386" if len(argv) <= 1 else argv[1]
#extra = "-vnc :0"
#image = "/mnt/hgfs/workspace/windows/WinXP.img"
#panda = Panda(extra_args=extra,qcow=image)

# Single arg of arch, defaults to i386
arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch,qcow=qcow,extra_args=extra,mem="1G")


# Make sure we log everything

vollog = logging.getLogger()
vollog.setLevel(1)
# Trim the console down by default
console = logging.StreamHandler()
console.setLevel(logging.FATAL)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)
vollog.addHandler(console)

from volatility.framework.automagic.stacker import LayerStacker


import logging
import sys
import traceback
from typing import List, Optional, Tuple

from volatility import framework
from volatility.framework import interfaces, constants, import_files
from volatility.framework.automagic import construct_layers
from volatility.framework.configuration import requirements
from volatility.framework.layers import physical
import urllib

vollog = logging.getLogger(__name__)

import traceback


from volatility.cli.text_renderer import CLIRenderer, optional, hex_bytes_as_text, display_disassembly
import datetime
from volatility.framework.renderers import format_hints
from io import StringIO

# Make sure we log everything

vollog = logging.getLogger()
vollog.setLevel(1)
# Trim the console down by default
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)
vollog.addHandler(console)



class StringTextRenderer(CLIRenderer):
    _type_renderers = {
        format_hints.Bin: optional(lambda x: "0b{:b}".format(x)),
        format_hints.Hex: optional(lambda x: "0x{:x}".format(x)),
        format_hints.HexBytes: optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: optional(display_disassembly),
        bytes: optional(lambda x: " ".join(["{0:2x}".format(b) for b in x])),
        datetime.datetime: optional(lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")),
        'default': optional(lambda x: "{}".format(x))
    }

    name = "string"

    def get_render_options(self):
        pass


    def render(self, grid: interfaces.renderers.TreeGrid):
        """Renders each column immediately to stdout.

        This does not format each line's width appropriately, it merely tab separates each field

        Args:
            grid: The TreeGrid object to render
        """
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = StringIO() #sys.stdout
        out = []

        line = []

        column_names = []
        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            #line.append("{}".format(column.name))
            column_names.append("{}".format(column.name))
        #outfd.write("\n{}\n".format("\t".join(line)))
        #outfd += "\n{}\n".format("\t".join(line))

        def visitor(node, accumulator):
            accumulator.write("\n")
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            #accumulator.write("*" * max(0, node.path_depth - 1) + ("" if (node.path_depth <= 1) else " "))
            #line = []
            line_output = {}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(column.type, self._type_renderers['default'])
                #line.append(renderer(node.values[column_index]))
                column_name = column_names[column_index]
                line_output[column_name] = node.values[column_index]
			
            out.append(line_output)
			
            #accumulator.write("{}".format("\t".join(line)))
            #accumulator.flush()
            return accumulator
    	

        if not grid.populated:
            grid.populate(visitor, outfd)
        else:
            grid.visit(node = None, function = visitor, initial_accumulator = outfd)

        #outfd.write("\n")
        return out

shouldstop = False
def stoprighttheresir():
	global shouldstop
	shouldstop = True


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
	

class FileHandler(urllib.request.BaseHandler):
	def default_open(self, req):
		if 'panda.panda' in req.full_url:
			length = panda.libpanda.ram_size
			if length > 0xc0000000:
				length += 0x40000000
			return PandaFile(length=length)
		else:
			return None
	def file_open(self, req):
		if 'panda.panda' in req.full_url:
			length = panda.libpanda.ram_size
			if length > 0xc0000000:
				length += 0x40000000
			return PandaFile(length=length)
		else:
			return None
	def file_close(self):
		return True

class PrintedProgress(object):
	"""A progress handler that prints the progress value and the description
	onto the command line."""

	def __init__(self):
		self._max_message_len = 0

	def __call__(self, progress: Union[int, float], description: str = None):
		"""A simple function for providing text-based feedback.

		.. warning:: Only for development use.

		Args:
			progress: Percentage of progress of the current procedure
		"""
		message = "\rProgress: {0: 7.2f}\t\t{1:}".format(round(progress, 2), description or '')
		message_len = len(message)
		self._max_message_len = max([self._max_message_len, message_len])
		sys.stderr.write(message + (' ' * (self._max_message_len - message_len)) + '\r')


class MuteProgress(PrintedProgress):
	"""A dummy progress handler that produces no output when called."""

	def __call__(self, progress: Union[int, float], description: str = None):
		pass


class CommandLine(interfaces.plugins.FileConsumerInterface):
	"""Constructs a command-line interface object for users to run plugins."""

	def __init__(self):
		self.output_dir = None

	def run(self, argstring):
		arg_arr = shlex.split(argstring)
		"""Executes the command line module, taking the system arguments,
		determining the plugin to run and then running it."""
		sys.stdout.write("Volatility 3 Framework {}\n".format(constants.PACKAGE_VERSION))

		volatility.framework.require_interface_version(1, 0, 0)

		renderers = dict([(x.name.lower(), x) for x in framework.class_subclasses(text_renderer.CLIRenderer)])

		parser = argparse.ArgumentParser(prog = 'volatility', description = "An open-source memory forensics framework")
		parser.add_argument("-c",
							"--config",
							help = "Load the configuration from a json file",
							default = None,
							type = str)
		parser.add_argument("--parallelism",
							help = "Enables parallelism (defaults to processes if no argument given)",
							nargs = '?',
							choices = ['processes', 'threads', 'off'],
							const = 'processes',
							default = None,
							type = str)
		parser.add_argument("-e",
							"--extend",
							help = "Extend the configuration with a new (or changed) setting",
							default = None,
							action = 'append')
		parser.add_argument("-p",
							"--plugin-dirs",
							help = "Semi-colon separated list of paths to find plugins",
							default = "",
							type = str)
		parser.add_argument("-s",
							"--symbol-dirs",
							help = "Semi-colon separated list of paths to find symbols",
							default = "",
							type = str)
		parser.add_argument("-v", "--verbosity", help = "Increase output verbosity", default = 0, action = "count")
		parser.add_argument("-l",
							"--log",
							help = "Log output to a file as well as the console",
							default = None,
							type = str)
		parser.add_argument("-o",
							"--output-dir",
							help = "Directory in which to output any generated files",
							default = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')),
							type = str)
		parser.add_argument("-q", "--quiet", help = "Remove progress feedback", default = False, action = 'store_true')
		parser.add_argument("-r",
							"--renderer",
							metavar = 'RENDERER',
							help = "Determines how to render the output ({})".format(", ".join(list(renderers))),
							default = "quick",
							choices = list(renderers))
		parser.add_argument("-f",
							"--file",
							metavar = 'FILE',
							default = None,
							type = str,
							help = "Shorthand for --single-location=file:// if single-location is not defined")
		parser.add_argument("--write-config",
							help = "Write configuration JSON file out to config.json",
							default = False,
							action = 'store_true')

		# We have to filter out help, otherwise parse_known_args will trigger the help message before having
		# processed the plugin choice or had the plugin subparser added.
		known_args = [arg for arg in arg_arr if arg != '--help' and arg != '-h']
		partial_args, _ = parser.parse_known_args(known_args)
		if partial_args.plugin_dirs:
			volatility.plugins.__path__ = [os.path.abspath(p)
										   for p in partial_args.plugin_dirs.split(";")] + constants.PLUGINS_PATH

		if partial_args.symbol_dirs:
			volatility.symbols.__path__ = [os.path.abspath(p)
										   for p in partial_args.symbol_dirs.split(";")] + constants.SYMBOL_BASEPATHS

		if partial_args.log:
			file_logger = logging.FileHandler(partial_args.log)
			file_logger.setLevel(1)
			file_formatter = logging.Formatter(datefmt = '%y-%m-%d %H:%M:%S',
											   fmt = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
			file_logger.setFormatter(file_formatter)
			vollog.addHandler(file_logger)
			vollog.info("Logging started")
		if partial_args.verbosity < 3:
			console.setLevel(30 - (partial_args.verbosity * 10))
		else:
			console.setLevel(10 - (partial_args.verbosity - 2))
		console.setLevel(0)

		vollog.info("Volatility plugins path: {}".format(volatility.plugins.__path__))
		vollog.info("Volatility symbols path: {}".format(volatility.symbols.__path__))

		# Set the PARALLELISM
		if partial_args.parallelism == 'processes':
			constants.PARALLELISM = constants.Parallelism.Multiprocessing
		elif partial_args.parallelism == 'threading':
			constants.PARALLELISM = constants.Parallelism.Threading
		else:
			constants.PARALLELISM = constants.Parallelism.Off

		# Do the initialization
		ctx = contexts.Context()  # Construct a blank context
		failures = framework.import_files(volatility.plugins,
										  True)  # Will not log as console's default level is WARNING
		if failures:
			parser.epilog = "The following plugins could not be loaded (use -vv to see why): " + \
							", ".join(sorted(failures))
			vollog.info(parser.epilog)
		automagics = automagic.available(ctx)

		plugin_list = framework.list_plugins()

		seen_automagics = set()
		configurables_list = {}
		for amagic in automagics:
			if amagic in seen_automagics:
				continue
			seen_automagics.add(amagic)
			if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
				self.populate_requirements_argparse(parser, amagic.__class__)
				configurables_list[amagic.__class__.__name__] = amagic

		subparser = parser.add_subparsers(title = "Plugins", dest = "plugin", action = HelpfulSubparserAction)
		for plugin in sorted(plugin_list):
			plugin_parser = subparser.add_parser(plugin, help = plugin_list[plugin].__doc__)
			self.populate_requirements_argparse(plugin_parser, plugin_list[plugin])
			configurables_list[plugin] = plugin_list[plugin]

		###
		# PASS TO UI
		###
		# Hand the plugin requirements over to the CLI (us) and let it construct the config tree

		# Run the argparser
		args = parser.parse_args(arg_arr)
		print(partial_args.verbosity)
		print(args.plugin, type(args.plugin))
		if args.plugin is None:
			parser.error("Please select a plugin to run")

		vollog.log(constants.LOGLEVEL_VVV, "Cache directory used: {}".format(constants.CACHE_PATH))

		plugin = plugin_list[args.plugin]
		base_config_path = "plugins"
		plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)

		# Special case the -f argument because people use is so frequently
		# It has to go here so it can be overridden by single-location if it's defined
		# NOTE: This will *BREAK* if LayerStacker, or the automagic configuration system, changes at all
		###
		if args.file:	
			file_name = os.path.abspath(args.file)
			if not os.path.exists(file_name) and "panda.panda" not in file_name:
				print("File does not exist: {}".format(file_name))
			else:
				single_location = "file:" + request.pathname2url(file_name)
				ctx.config['automagic.LayerStacker.single_location'] = single_location

		# UI fills in the config, here we load it from the config file and do it before we process the CL parameters
		if args.config:
			with open(args.config, "r") as f:
				json_val = json.load(f)
				ctx.config.splice(plugin_config_path, interfaces.configuration.HierarchicalDict(json_val))

		self.populate_config(ctx, configurables_list, args, plugin_config_path)

		if args.extend:
			pdb.set_trace()
			for extension in args.extend:
				if '=' not in extension:
					raise ValueError("Invalid extension (extensions must be of the format \"conf.path.value='value'\")")
				address, value = extension[:extension.find('=')], json.loads(extension[extension.find('=') + 1:])
				ctx.config[address] = value

		# It should be up to the UI to determine which automagics to run, so this is before BACK TO THE FRAMEWORK
		automagics = automagic.choose_automagic(automagics, plugin)
		self.output_dir = args.output_dir

		###
		# BACK TO THE FRAMEWORK
		###
		try:
			progress_callback = PrintedProgress()
			if args.quiet:
				progress_callback = MuteProgress()

			pdb.set_trace()
			constructed = plugins.construct_plugin(ctx, automagics, plugin, base_config_path, progress_callback, self)
		#	return (ctx, automagics, plugin, base_config_path, progress_callback, self)

			if args.write_config:
				vollog.debug("Writing out configuration data to config.json")
				with open("config.json", "w") as f:
					json.dump(dict(constructed.build_configuration()), f, sort_keys = True, indent = 2)
			#return StringTextRenderer().render(constructed.run())
			return constructed
		except exceptions.UnsatisfiedException as excp:
			self.process_exceptions(excp)
			parser.exit(1, "Unable to validate the plugin requirements: {}\n".format([x for x in excp.unsatisfied]))

	def process_exceptions(self, excp):
		"""Provide useful feedback if an exception occurs."""
		# Add a blank newline
		print("")
		translation_failed = False
		symbols_failed = False
		for config_path in excp.unsatisfied:
			translation_failed = translation_failed or isinstance(
				excp.unsatisfied[config_path], configuration.requirements.TranslationLayerRequirement)
			symbols_failed = symbols_failed or isinstance(excp.unsatisfied[config_path],
														  configuration.requirements.SymbolTableRequirement)

			print("Unsatisfied requirement {}: {}".format(config_path, excp.unsatisfied[config_path].description))

		if symbols_failed:
			print("\nA symbol table requirement was not fulfilled.	Please verify that:\n"
				  "\tYou have the correct symbol file for the requirement\n"
				  "\tThe symbol file is under the correct directory or zip file\n"
				  "\tThe symbol file is named appropriately or contains the correct banner\n")
		if translation_failed:
			print("\nA translation layer requirement was not fulfilled.  Please verify that:\n"
				  "\tA file was provided to create this layer (by -f, --single-location or by config)\n"
				  "\tThe file exists and is readable\n"
				  "\tThe necessary symbols are present and identified by volatility")

	def populate_config(self, context: interfaces.context.ContextInterface,
						configurables_list: Dict[str, interfaces.configuration.ConfigurableInterface],
						args: argparse.Namespace, plugin_config_path: str) -> None:
		"""Populate the context config based on the returned args.

		We have already determined these elements must be descended from ConfigurableInterface

		Args:
			context: The volatility context to operate on
			configurables_list: A dictionary of configurable items that can be configured on the plugin
			args: An object containing the arguments necessary
			plugin_config_path: The path within the context's config containing the plugin's configuration
		"""
		vargs = vars(args)
		for configurable in configurables_list:
			for requirement in configurables_list[configurable].get_requirements():
				value = vargs.get(requirement.name, None)
				if value is not None:
					if isinstance(requirement, requirements.URIRequirement):
						if isinstance(value, str):
							if not parse.urlparse(value).scheme:
								if not os.path.exists(value):
									raise TypeError("Non-existant file {} passed to URIRequirement".format(value))
								value = "file://" + request.pathname2url(os.path.abspath(value))
					if isinstance(requirement, requirements.ListRequirement):
						if not isinstance(value, list):
							raise TypeError("Configuration for ListRequirement was not a list")
						value = [requirement.element_type(x) for x in value]
					if not inspect.isclass(configurables_list[configurable]):
						config_path = configurables_list[configurable].config_path
					else:
						# We must be the plugin, so name it appropriately:
						config_path = plugin_config_path
					extended_path = interfaces.configuration.path_join(config_path, requirement.name)
					context.config[extended_path] = value
					pdb.set_trace()

	def consume_file(self, filedata: interfaces.plugins.FileInterface):
		"""Consumes a file as produced by a plugin."""
		if self.output_dir is None:
			raise ValueError("Output directory has not been correctly specified")
		os.makedirs(self.output_dir, exist_ok = True)

		pref_name_array = filedata.preferred_filename.split('.')
		filename, extension = os.path.join(self.output_dir, '.'.join(pref_name_array[:-1])), pref_name_array[-1]
		output_filename = "{}.{}".format(filename, extension)

		if not os.path.exists(output_filename):
			with open(output_filename, "wb") as current_file:
				current_file.write(filedata.data.getvalue())
				vollog.log(logging.INFO, "Saved stored plugin file: {}".format(output_filename))
		else:
			vollog.warning("Refusing to overwrite an existing file: {}".format(output_filename))

	def populate_requirements_argparse(self, parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup],
									   configurable: Type[interfaces.configuration.ConfigurableInterface]):
		"""Adds the plugin's simple requirements to the provided parser.

		Args:
			parser: The parser to add the plugin's (simple) requirements to
			configurable: The plugin object to pull the requirements from
		"""
		pdb.set_trace()
		if not issubclass(configurable, interfaces.configuration.ConfigurableInterface):
			raise TypeError("Expected ConfigurableInterface type, not: {}".format(type(configurable)))

		# Construct an argparse group

		for requirement in configurable.get_requirements():
			additional = {}  # type: Dict[str, Any]
			if not isinstance(requirement, interfaces.configuration.RequirementInterface):
				raise TypeError("Plugin contains requirements that are not RequirementInterfaces: {}".format(
					configurable.__name__))
			if isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
				additional["type"] = requirement.instance_type
				if isinstance(requirement, requirements.IntRequirement):
					additional["type"] = lambda x: int(x, 0)
				if isinstance(requirement, requirements.BooleanRequirement):
					additional["action"] = "store_true"
					if "type" in additional:
						del additional["type"]
			elif isinstance(requirement, volatility.framework.configuration.requirements.ListRequirement):
				# This is a trick to generate a list of values
				additional["type"] = lambda x: x.split(',')
			elif isinstance(requirement, volatility.framework.configuration.requirements.ChoiceRequirement):
				additional["type"] = str
				additional["choices"] = requirement.choices
			else:
				continue
			parser.add_argument("--" + requirement.name.replace('_', '-'),
								help = requirement.description,
								default = requirement.default,
								dest = requirement.name,
								required = not requirement.optional,
								**additional)


# We shouldn't really steal a private member from argparse, but otherwise we're just duplicating code
class HelpfulSubparserAction(argparse._SubParsersAction):
	"""Class to either select a unique plugin based on a substring, or identify
	the alternatives."""

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		# We don't want the action self-check to kick in, so we remove the choices list, the check happens in __call__
		self.choices = None

	def __call__(self, parser, namespace, values, option_string = None):
		parser_name = values[0]
		arg_strings = values[1:]

		# set the parser name if requested
		if self.dest is not argparse.SUPPRESS:
			setattr(namespace, self.dest, parser_name)

		matched_parsers = [name for name in self._name_parser_map if parser_name in name]

		if len(matched_parsers) < 1:
			msg = 'invalid choice {} (choose from {})'.format(parser_name, ', '.join(self._name_parser_map))
			raise argparse.ArgumentError(self, msg)
		if len(matched_parsers) > 1:
			msg = 'plugin {} matches multiple plugins ({})'.format(parser_name, ', '.join(matched_parsers))
			raise argparse.ArgumentError(self, msg)
		parser = self._name_parser_map[matched_parsers[0]]
		setattr(namespace, 'plugin', matched_parsers[0])

		# parse all the remaining options into the namespace
		# store any unrecognized options on the object, so that the top
		# level parser can decide what to do with them

		# In case this subparser defines new defaults, we parse them
		# in a new namespace object and then update the original
		# namespace for the relevant parts.
		subnamespace, arg_strings = parser.parse_known_args(arg_strings, None)
		for key, value in vars(subnamespace).items():
			setattr(namespace, key, value)

		if arg_strings:
			vars(namespace).setdefault(argparse._UNRECOGNIZED_ARGS_ATTR, [])
			getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)

from time import time
from copy import copy, deepcopy

timechange = 5
oldtime = time()
plugin = "linux.pstree.PsTree"
constructed = None 
construction_equipment = None
construction_equipment_original = None
vmlinux = None
vmlinux_original = None

total_time = 0
number_runs = 0

@panda.cb_asid_changed()
def on_asid_change(env, old_asid, new_asid):
	global oldtime, timechange, constructed, plugin, total_time, number_runs, construction_equipment, construction_equipment_original, constructed_original, vmlinux, vmlinux_original, _dict, _resolved, _resolved_symbols, context_original, symbol_space_original
	if time() - oldtime > timechange:
		a = time()
		if not vmlinux:
			constructed_original = CommandLine().run("-q -f panda.panda " + plugin)
			print("doing ASLR stuff")
			linux.LinuxUtilities.aslr_mask_symbol_table(constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'])
			vmlinux = contexts.Module(constructed_original.context, constructed_original.config['vmlinux'],constructed_original.config['primary'], 0)

		LinearlyMappedLayer.read.cache_clear()		
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

