import ctypes as ct
import logging
import os
import re
import types
# noinspection PyUnresolvedReferences
from collections import OrderedDict
# noinspection PyProtectedMember
from threading import Thread, Event, _Event, current_thread

from bcc import BPF

from pyebpf.helpers import assert_type
from pyebpf.normalizers import normalize_event


class EBPFProgramDescriptor(object):
    """ A wrapper around a program text and its extra parameters as a ctypes data class """

    def __init__(self, program_text, ctypes_data_class):
        # type: (types.StringTypes, types.TypeType) -> None
        """
        :param program_text: str - BPF-program text
        :param ctypes_data_class: ctypes.Structure - A Data class representing any extra parameters for the ebpf routine
        """
        assert_type(types.StringTypes, program_text=program_text)
        assert_type(types.TypeType, ctypes_data_class=ctypes_data_class)

        self.program_text = program_text
        self.ctypes_data_class = ctypes_data_class


class AttachedKProbeDescriptor(object):
    """ A wrapper around an event, a BPF object and an optional managed polling thread """

    def __init__(self, event, bpf, polling_thread_event=None):
        # type: (types.StringTypes, BPF, [Event]) -> None

        """
        :param event: str - An event name
        :param bpf: BPF - A BPF object with a compiled module
        :param polling_thread_event: Event - An event to set once the kprobe is detached
        """

        assert_type(types.StringTypes, event=event)
        assert_type(BPF, bpf=bpf)

        if polling_thread_event is not None:
            assert_type(_Event, polling_thread_event=polling_thread_event)

        self.event = normalize_event(event)
        self.bpf = bpf
        self.polling_thread_event = polling_thread_event


class NativeArgument(object):
    """ Represents an argument that is passed to a native function. """

    def __init__(self, native_type_as_string, name, ctypes_type):
        # type: (types.StringTypes, types.StringTypes, types.TypeType) -> None

        """
        :param native_type_as_string: str - A string representing the c-type of the argument, e.g. 'unsigned int'
        :param name: str - The name of the argument
        :param ctypes_type: The type represented as a ctypes type
        """
        assert_type(types.StringTypes, native_type_as_string=native_type_as_string)
        assert_type(types.StringTypes, name=name)
        assert_type(types.TypeType, ctypes_type=ctypes_type)

        self.native_type_as_string = native_type_as_string
        self.name = name
        self.ctypes_type = ctypes_type

    def is_string(self):
        # type: () -> types.BooleanType
        """
        :return: True if native type is a char pointer
        :rtype: bool
        """
        return NativeArgument.is_native_type_a_string(self.native_type_as_string)

    @staticmethod
    def is_native_type_a_string(native_type_as_string):
        # type: () -> types.BooleanType
        """
        :param: native_type_as_string: str - A string representing a native type
        :return: True if native type is a char pointer
        :rtype: bool
        """

        return 'char' in native_type_as_string and '*' in native_type_as_string

    def __repr__(self):
        return '{} {}'.format(self.native_type_as_string, self.name)

    def __str__(self):
        return self.__repr__()


class EBPFWrapper(BPF):
    # The syscall for-file template
    SYSCALL_FORMAT_FILE_TEMPLATE = os.getenv(
        'SYSCALL_FORMAT_FILE_TEMPLATE', '/sys/kernel/debug/tracing/events/syscalls/sys_enter_{syscall_name}/format'
    )

    # Max array size to be allocated when spotting strings as syscall arguments
    MAX_ARRAY_SIZE = int(os.getenv(
        'MAX_ARRAY_SIZE', 128
    ))

    # eBPF Arguments are capped, as they are passed via registers
    MAX_PASSED_ARGS = int(os.getenv('MAX_PASSED_ARGS', 6))

    # The default offset that all syscall-arguments (inclusive) are skipped till
    SKIP_SYSCALL_ARGS_TILL_OFFSET = int(os.getenv('SKIP_SYSCALL_ARGS_TILL_OFFSET', 16))

    # Known syscall event aliases (e.g. open -> openat)
    SYSCALL_EVENT_ALIASES = {
        'open': 'openat'
    }

    # Kprobe Event Syscall Prefix
    KRPOBE_EVENT_SYSCALL_PREFIX = os.getenv('KRPOBE_EVENT_SYSCALL_PREFIX', 'do_')

    # Default data structure members
    # noinspection PyTypeChecker
    DEFAULT_DATA_STRUCTURE_MEMBERS = [
        NativeArgument('u64', 'current_time_ns', ct.c_uint64),
        NativeArgument('u32', 'process_id', ct.c_uint32),
        NativeArgument('u32', 'thread_id', ct.c_uint32),
        NativeArgument('u32', 'group_id', ct.c_uint32),
        NativeArgument('u32', 'user_id', ct.c_uint32),
        NativeArgument('char*', 'process_name', (ct.c_char * 16)),
    ]

    # A string representing a type, or a byte size - to a ctypes type
    C_TYPE_MAPPING = {
        'char': ct.c_char,
        'short': ct.c_short,
        'int': ct.c_int,
        'long': ct.c_long,
        'float': ct.c_float,
        'double': ct.c_double,

        'umode_t': ct.c_ushort,
        'unsigned char': ct.c_ubyte,
        'unsigned short': ct.c_ushort,
        'unsigned int': ct.c_uint,
        'unsigned long': ct.c_ulong,
        'unsigned long long': ct.c_ulonglong,

        1: ct.c_char,
        2: ct.c_short,
        4: ct.c_int16,
        8: ct.c_int32,
        16: ct.c_int64
    }

    # Dummy program that is used in order to initialize internal data structures of parent
    _DUMMY_PROGRAM = 'int dummy(struct pt_regs* ctx) { return 0; }'

    logger = logging.getLogger('ebpf_wrapper')

    # noinspection PyMissingConstructor
    def __init__(self, **kwargs):
        # type: (**types.ObjectType) -> None

        self._attached_kprobes = {}

        log_level = kwargs.get('log_level', logging.INFO)
        self.logger.setLevel(log_level)

        if kwargs:
            self.logger.debug('Arguments were passed during init - will instantiate parent')
            super(EBPFWrapper, self).__init__(**kwargs)
        else:
            super(EBPFWrapper, self).__init__(text=self._DUMMY_PROGRAM)

    def detach_kprobe(self, event):
        # type: (types.StringTypes) -> None
        """
        Detaches kprobes associated with the event nmae.

        :param event: str - Event name to detach kprobes of
        """
        assert_type(types.StringTypes, event=event)

        event = normalize_event(event)

        if event not in self._attached_kprobes:
            self.logger.info('{} is not an attached kprobe'.format(event))
            return

        kprobes_for_event = self._attached_kprobes.get(event, [])
        kprobes_for_event_copy = list(kprobes_for_event)

        for idx, descriptor in enumerate(kprobes_for_event_copy):
            # noinspection PyBroadException
            try:
                self.logger.info('Detaching kprobe with event={} bpf_idx={}'.format(event, idx))
                if descriptor.bpf == self:
                    # noinspection PyUnresolvedReferences
                    super(EBPFWrapper, self).detach_kprobe(event)
                else:
                    descriptor.bpf.detach_kprobe(event)

                if descriptor.polling_thread_event is not None:
                    descriptor.polling_thread_event.set()

                kprobes_for_event.pop(idx)
            except Exception:
                self.logger.exception('Failed detaching kprobe for event={} bpf_idx={}; Continuing'.format(event, idx))

        if not kprobes_for_event:
            self._attached_kprobes.pop(event)

    # noinspection PyMethodOverriding
    def attach_kprobe(self, event, fn=None, implicitly_add_syscall_args=True, **kwargs):
        # type: (types.StringTypes, types.FunctionType, types.BooleanType, **types.ObjectType) -> None
        """
        Attaches a kernel probe to a given python function

        :param event: Name of the event to attach to
        :param fn: Python function to invoke
        :param implicitly_add_syscall_args: If True, will try to implicitly generate the syscall arguments,
                                            copying them from our ebpf routine back to user-space
        """
        assert_type(types.StringTypes, event=event)
        if fn is not None:
            assert_type(types.FunctionType, fn=fn)

        event = normalize_event(event)
        attached_kprobe_descriptor = None

        try:
            if not fn:
                self.logger.debug('Function was not passed - fallbacking to default implementation')
                attached_kprobe_descriptor = AttachedKProbeDescriptor(event, self)
                return super(EBPFWrapper, self).attach_kprobe(event, **kwargs)

            event_without_syscall_prefix = None

            # noinspection PyUnresolvedReferences
            for syscall_prefix in self._syscall_prefixes:
                syscall_prefix = syscall_prefix.lower()
                if event.startswith(syscall_prefix) or \
                        event.startswith(self.KRPOBE_EVENT_SYSCALL_PREFIX + syscall_prefix):
                    event_without_syscall_prefix = event \
                        .replace(syscall_prefix, '') \
                        .replace(self.KRPOBE_EVENT_SYSCALL_PREFIX, '')
                    break

            if event_without_syscall_prefix is None:
                self.logger.debug('Event is not prefixed with a known syscall prefix - '
                                  'fallbacking to default implementation')
                attached_kprobe_descriptor = AttachedKProbeDescriptor(event, self)
                return super(EBPFWrapper, self).attach_kprobe(event, **kwargs)

            event_without_syscall_prefix = self._replace_event_alias_if_needed(event_without_syscall_prefix)
            attached_kprobe_descriptor = self._attach_kprobe_with_managed_polling_thread(event,
                                                                                         event_without_syscall_prefix,
                                                                                         fn,
                                                                                         implicitly_add_syscall_args)
        finally:
            if attached_kprobe_descriptor is not None:
                self._attached_kprobes.setdefault(event, []).append(attached_kprobe_descriptor)

    def _replace_event_alias_if_needed(self, event_without_syscall_prefix):
        # type: (types.StringTypes) -> types.StringTypes
        """
        Follows known event aliases (if any) and replaces them, or return the origin event

        :param event_without_syscall_prefix: str - The event without a syscall prefix
        :return: str - The dereferenced event from the alias, or the original event if no alias was found
        """
        assert_type(types.StringTypes, event_without_syscall_prefix=event_without_syscall_prefix)

        event_alias = self.SYSCALL_EVENT_ALIASES.get(event_without_syscall_prefix, None)
        if event_alias is not None:
            self.logger.debug('Event is an alias, will replace "{}" with "{}"'.format(event_without_syscall_prefix,
                                                                                      event_alias))
            event_without_syscall_prefix = event_alias

        return event_without_syscall_prefix

    def _attach_kprobe_with_managed_polling_thread(self, event, event_without_syscall_prefix, fn,
                                                   implicitly_add_syscall_args):
        # type: (types.StringTypes, types.StringTypes, types.FunctionType, types.BooleanType) -> AttachedKProbeDescriptor
        """
        Attaches a kprobe with a given event, and spawns a daemon thread that polls on the kprobe map and calls
        the passed function as a callback.

        :param event: str - An event
        :param event_without_syscall_prefix: str - An event without its syscall prefix
        :param fn: function - A function to call once the kprobe was invoked
        :param implicitly_add_syscall_args: If True, will try to implicitly generate the syscall arguments
        :return: An AttachedKProbeDescriptor object that wraps the event, the bpf object and the polling thread
        :rtype: AttachedKProbeDescriptor
        """
        assert_type(types.StringTypes, event=event)
        assert_type(types.StringTypes, event_without_syscall_prefix=event_without_syscall_prefix)
        assert_type(types.FunctionType, fn=fn)

        function_name = fn.__name__
        self.logger.debug('Attaching kprobe to event={}'.format(event))
        program_descriptor = self._generate_program_descriptor(event_without_syscall_prefix, function_name,
                                                               implicitly_add_syscall_args)
        bpf = BPF(text=program_descriptor.program_text)
        bpf.attach_kprobe(event=event, fn_name=function_name)

        detach_event = Event()
        t = Thread(target=self._read_buffer_pool, name='{}::{}_thread'.format(event, function_name),
                   args=(bpf, fn, program_descriptor.ctypes_data_class, detach_event))
        t.setDaemon(True)
        t.start()

        return AttachedKProbeDescriptor(event, bpf, detach_event)

    def _generate_program_descriptor(self, event, function_name, implicitly_add_syscall_args):
        # type: (types.StringTypes, types.StringTypes) -> EBPFProgramDescriptor
        """
        :param event: str - An event / syscall name
        :param function_name: A function name (The ebpf function will use this name)
        :param implicitly_add_syscall_args: If True, will try to implicitly generate the syscall arguments
        :return: A program text that copies all of the syscall parameters back to user-space
        :rtype: BPFProgramDescriptor
        """
        assert_type(types.StringTypes, event=event)
        assert_type(types.StringTypes, function_name=function_name)

        syscall_args = []
        if not implicitly_add_syscall_args:
            self.logger.debug('Implicit syscall argument generation is disabled')
        else:
            syscall_args = self._get_syscall_arguments(event)

        program_text = '''
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);                    
'''

        data_struct = self._generate_data_struct(syscall_args)
        program_text += '{data_struct}'.format(data_struct=data_struct)

        data_struct_copy_body = self._generate_data_struct_copy_body(syscall_args)
        function_signature = self._generate_function_signature(function_name, syscall_args)
        program_text += '''
%(func_signature)s {
    struct data_t data = {};
                
    %(data_struct_copy_body)s           
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
''' % dict(func_signature=function_signature, data_struct_copy_body=data_struct_copy_body)

        data_class = self._generate_data_class(syscall_args)
        return EBPFProgramDescriptor(program_text, data_class)

    def _get_syscall_arguments(self, syscall_name, skip_till_offset=SKIP_SYSCALL_ARGS_TILL_OFFSET):
        # type: (types.StringTypes, types.IntType) -> types.ListType
        """

        :param syscall_name: str - The name of the syscall to get the arguments for
        :param skip_till_offset: An offset that all arguments (inclusive) till it, are skipped
        :return: A list of NativeArgument objects, representing the syscall arguments, or None, if parsing fails
        :rtype: list
        """

        assert_type(types.StringTypes, syscall_name=syscall_name)
        assert_type(types.IntType, skip_till_offset=skip_till_offset)

        format_file_path = self.SYSCALL_FORMAT_FILE_TEMPLATE.format(syscall_name=syscall_name)
        self.logger.debug('Will try to read syscall format file={}'.format(format_file_path))

        # noinspection PyBroadException
        try:
            args = []

            with open(format_file_path) as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped.startswith('field:'):
                        continue

                    format_parts = [x.strip() for x in stripped.replace('field:', '').split(';') if x.strip()]
                    assert len(format_parts) == 4, 'Failed parsing syscall field format; ' \
                                                   'Expected a 4 parts separated by ";"'

                    self.logger.debug('Parsing field line={}'.format(line))

                    offset = format_parts[1]
                    assert offset.startswith('offset:'), 'Expected offset part to start with "offset:"'

                    offset_match = re.findall('\d+', offset)
                    assert offset_match and len(offset_match) == 1, 'Expected offset part to contain a single number'

                    offset_num = int(offset_match[0])
                    if offset_num < skip_till_offset:
                        self.logger.debug('Skipping field with offset={}'.format(offset_num))
                        continue

                    size = format_parts[2]
                    assert size.startswith('size:'), 'Expected size part to start with "size:"'

                    size_match = re.findall('\d+', size)
                    assert size_match and len(size_match) == 1, 'Expected size part to contain a single number'

                    type_size = int(size_match[0])

                    type_and_name = format_parts[0]
                    splat = type_and_name.split(' ')
                    assert len(splat) >= 2, 'Expected type and name part to contain at least two spaces'

                    c_type = ' '.join(splat[:-1])
                    name = splat[-1]

                    native_arg = NativeArgument(c_type, name, self._resolve_ctype(c_type, type_size))
                    self.logger.debug('Parsed native arg={}'.format(native_arg))
                    args.append(native_arg)

                    if len(args) > self.MAX_PASSED_ARGS:
                        self.logger.warn("We've populated the maximum number of arguments ({}); "
                                         "Will return a partial argument list".format(self.MAX_PASSED_ARGS))
                        break
        except Exception as e:
            self.logger.error('Failed parsing syscall format file from path={} err={}; '
                              'will return None'.format(format_file_path, e.message))
            return []

        return args

    def _generate_data_struct(self, syscall_args):
        # type: (types.ListType) -> types.StringTypes
        """
        Generates a data structure representing string that is copied from kernel-space to user-space.

        :param syscall_args: List of syscall args
        :return: Data structure string to be shared from kernel space to user space (Could be empty)
        :rtype: str
        """
        assert_type(types.ListType, syscall_args=syscall_args)

        data_struct_template = '''
struct data_t {
    %(syscall_args)s;
};
            
'''

        formatted_args = OrderedDict()
        for arg in (self.DEFAULT_DATA_STRUCTURE_MEMBERS + syscall_args):
            if arg.name in formatted_args:
                self.logger.warn('Duplicate arg found - will take the last match')

            if arg.is_string():
                self.logger.debug('Spotted a string - implicitly converting to char array')
                # noinspection PyBroadException
                try:
                    # noinspection PyUnresolvedReferences, PyProtectedMember
                    array_size = arg.ctypes_type._length_
                except Exception:
                    # Try get array size from ctypes type best-effortly
                    array_size = self.MAX_ARRAY_SIZE

                # noinspection PyTypeChecker
                arg = NativeArgument(
                    'char',
                    '{arg_name}[{array_size}]'.format(arg_name=arg.name, array_size=array_size),
                    ct.c_char * array_size
                )
            formatted_args[arg.name] = str(arg)

        return data_struct_template % dict(syscall_args=';\n    '.join(formatted_args.values()))

    def _generate_data_struct_copy_body(self, syscall_args):
        # type: (types.ListType) -> types.StringTypes
        """
        Generates a string representing the copying of the syscall arguments to our shared data-structure

        :param syscall_args: List of syscall args
        :return: A string representing all copying to be made from syscall arguments
                (that are passed to our ebpf handler) back to user mode
        :rtype: str
        """
        assert_type(types.ListType, syscall_args=syscall_args)

        body = '''
    data.current_time_ns = bpf_ktime_get_ns();
    data.process_id = bpf_get_current_pid_tgid() >> 32;
    data.thread_id = (u32) bpf_get_current_pid_tgid();
    data.group_id = bpf_get_current_uid_gid() >> 32;
    data.user_id = (u32) bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.process_name, sizeof(data.process_name));         
'''

        for arg in syscall_args:
            if arg.is_string():
                self.logger.debug('Spotted a string - will use bpf_probe_read to copy it')
                body += 'bpf_probe_read(&data.{arg_name}, sizeof(data.{arg_name}), (void*){arg_name});\n    '.format(
                    arg_name=arg.name)
            else:
                body += 'data.{arg_name} = {arg_name};\n    '.format(arg_name=arg.name)

        return body

    def _generate_data_class(self, syscall_args):
        # type: (types.ListType) -> types.TypeType

        """
        Generates a ctypes data-class given the syscall arguments

        :param syscall_args: list - A list of NativeArgument objects, representing syscall arguments
                                    that are passed to our ebpf routine
        :return: ctypes class that the members to copy from our ebpf routine back to user-space
        :rtype: type
        """
        assert_type(types.ListType, syscall_args=syscall_args)
        fields = [(arg.name, arg.ctypes_type) for arg in (self.DEFAULT_DATA_STRUCTURE_MEMBERS + syscall_args)]

        # noinspection PyUnresolvedReferences
        class Data(ct.Structure):
            _fields_ = fields

        self.logger.debug('Generated data class fields: {}'.format(fields))

        return Data

    # noinspection PyTypeChecker
    def _resolve_ctype(self, type_as_string, type_size):
        # type: (types.StringTypes, types.IntType) -> types.TypeType

        """
        Given a string representing a type, and the type size - resolve a ctypes type

        :param type_as_string: str - A string representing a native type
        :param type_size: The size of the underlying native type
        :return: A ctypes type representing the native type
        :rtype: type
        """
        assert_type(types.StringTypes, type_as_string=type_as_string)
        assert_type(types.IntType, type_size=type_size)

        # Qualifiers are irrelevant
        type_as_string = type_as_string.replace('const', '').strip()

        if NativeArgument.is_native_type_a_string(type_as_string):
            self.logger.debug('Spotted a string - will use an array instead')
            return ct.c_char * self.MAX_ARRAY_SIZE
        else:
            return self.C_TYPE_MAPPING.get(
                type_as_string,
                self.C_TYPE_MAPPING.get(type_size, ct.c_int)
            )

    @staticmethod
    def _generate_function_signature(function_name, syscall_args):
        # type: (types.StringTypes, types.ListType) -> types.StringTypes
        """

        :param function_name: The name of the ebpf function
        :param syscall_args: List of syscall arguments
        :return: A string representing the ebpf function signature (Including the syscall arguments, and the mandatory
                registers context struct)
        :rtype: str
        """
        assert_type(types.StringTypes, function_name=function_name)
        assert_type(types.ListType, syscall_args=syscall_args)

        syscall_args = map(lambda x: str(x), syscall_args)
        base_function_signature = 'int {function_name} (struct pt_regs* ctx'.format(function_name=function_name)
        if syscall_args:
            base_function_signature += ', {syscall_args}'.format(syscall_args=', '.join(syscall_args))

        base_function_signature += ')'
        return base_function_signature

    def _read_buffer_pool(self, bpf, callback, data_class, detach_event):
        # type: (BPF, types.FunctionType, types.TypeType, _Event) -> None

        """
        A routine that will be called from a separate thread, that will call a given python callback, till
        detach_event is set.

        :param bpf: A BPF instance
        :param callback: A callback to call to whenever our kprobe was invoked
        :param data_class: A ctypes data class to pass to the routine as a kwarg
        :param detach_event: An event to check against, once this is set, our thread will stop polling
        """
        assert_type(BPF, bpf=bpf)
        assert_type(types.FunctionType, callback=callback)
        assert_type(types.TypeType, data_class=data_class)
        assert_type(_Event, detach_event=detach_event)

        thread_name = current_thread().getName()

        def call_callback(cpu, data, size):
            # type: (types.IntType, types.TypeType, types.IntType) -> None

            """
            On every BPF map poll, we'll call this wrapper, which will call the passed callback.

            :param cpu: CPU #
            :param data: Shread data class from our EBPF routine
            :param size: Size of data class, in bytes
            """
            # noinspection PyUnresolvedReferences,PyBroadException
            try:
                # noinspection PyUnresolvedReferences
                data = ct.cast(data, ct.POINTER(data_class)).contents
            except Exception:
                # Try cast data best effortly
                pass

            if not detach_event.is_set():
                # noinspection PyBroadException
                try:
                    callback(cpu=cpu, data=data, size=size)
                except Exception:
                    # Best-effort callback
                    self.logger.exception('Failed calling callback')

        # noinspection PyUnresolvedReferences
        bpf['events'].open_perf_buffer(call_callback)
        while not detach_event.is_set():
            # noinspection PyBroadException
            try:
                # noinspection PyUnresolvedReferences
                bpf.perf_buffer_poll()
            except Exception:
                # Best-effort polling, if we fail - we should kill the thread
                self.logger.exception('Failed polling from bpf map')
                break

        self.logger.info('Polling thread is detached name={}'.format(thread_name))
