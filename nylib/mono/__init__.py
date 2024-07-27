import functools

from .defines import *


class _MonoObj:
    def __new__(cls, ptr):
        if not ptr:
            return None
        return super().__new__(cls)

    def __init__(self, ptr):
        self.ptr = ptr

    def __eq__(self, other):
        if isinstance(other, _MonoObj):
            return self.ptr == other.ptr
        return False


class MonoObject(_MonoObj):
    def init(self):
        MonoApi.get_instance().mono_runtime_object_init(self.ptr)

    @functools.cached_property
    def cls(self):
        return MonoClass(MonoApi.get_instance().mono_object_get_class(self.ptr))


class MonoMethodHeader(_MonoObj):
    @functools.cached_property
    def il_code(self):
        res = MonoApi.get_instance().mono_method_header_get_code(self.ptr, ctypes.byref(code := ctypes.c_uint32()), None)
        return res, code.value


class MonoType(_MonoObj):
    @functools.cached_property
    def name(self) -> str:
        return MonoApi.get_instance().mono_type_get_name(self.ptr).decode('utf-8')

    @functools.cached_property
    def cls(self):
        return MonoClass(MonoApi.get_instance().mono_type_get_class(self.ptr))

    @functools.cached_property
    def cls_from_ptr(self):
        return MonoClass(MonoApi.get_instance().mono_ptr_class_get(self.ptr))

    @functools.cached_property
    def type_from_ptr(self):
        return MonoType(MonoApi.get_instance().mono_type_get_ptr_type(self.ptr))

    @functools.cached_property
    def type(self) -> int:
        return MonoApi.get_instance().mono_type_get_type(self.ptr)


class MonoField(_MonoObj):
    @functools.cached_property
    def type(self):
        return MonoType(MonoApi.get_instance().mono_field_get_type(self.ptr))

    @functools.cached_property
    def name(self) -> str:
        return MonoApi.get_instance().mono_field_get_name(self.ptr).decode('utf-8')

    @functools.cached_property
    def parent(self):
        return MonoApi.get_instance().mono_field_get_parent(self.ptr)

    @functools.cached_property
    def offset(self):
        return MonoApi.get_instance().mono_field_get_offset(self.ptr)

    @functools.cached_property
    def flags(self):
        return MonoApi.get_instance().mono_field_get_flags(self.ptr)


class MonoMethod(_MonoObj):
    @functools.cached_property
    def name(self) -> str:
        return MonoApi.get_instance().mono_method_get_name(self.ptr).decode('utf-8')

    @functools.cached_property
    def full_name(self) -> str:
        return MonoApi.get_instance().mono_method_get_full_name(self.ptr).decode('utf-8')

    @functools.cached_property
    def flags(self):
        return MonoApi.get_instance().mono_method_get_flags(self.ptr)

    @functools.cached_property
    def cls(self):
        return MonoClass(MonoApi.get_instance().mono_method_get_class(self.ptr))

    @functools.cached_property
    def header(self):
        return MonoMethodHeader(MonoApi.get_instance().mono_method_get_header(self.ptr))

    def compile(self):
        api = MonoApi.get_instance()
        if api.is_il2cpp:
            return self.ptr
        cls = self.cls
        if api.mono_class_is_generic(cls.ptr):
            return api.mono_compile_method(self.ptr)
        return None

    def free(self):
        MonoApi.get_instance().mono_free_method(self.ptr)

    def disasm(self):
        api = MonoApi.get_instance()
        if api.is_il2cpp:
            raise NotImplementedError('il2cpp disasm not implemented')
        il_code, code = self.header.il_code
        disassembly = api.mono_disasm_code(None, self.ptr, il_code, il_code + code)
        return disassembly.decode('utf-8')



class MonoClass(_MonoObj):
    def new_object(self):
        api = MonoApi.get_instance()
        if api.is_il2cpp:
            return MonoObject(api.mono_object_new(self.ptr, self.ptr))
        else:
            domain = (api.mono_get_root_domain or api.mono_domain_get)()
            return MonoObject(api.mono_object_new(domain, self.ptr))

    @functools.cached_property
    def name(self) -> str:
        return MonoApi.get_instance().mono_class_get_name(self.ptr).decode('utf-8')

    @functools.cached_property
    def parent(self):
        return MonoClass(MonoApi.get_instance().mono_class_get_parent(self.ptr))

    @functools.cached_property
    def nesting_type(self):
        return MonoClass(MonoApi.get_instance().mono_class_get_nesting_type(self.ptr))

    @functools.cached_property
    def namespace(self) -> str:
        return MonoApi.get_instance().mono_class_get_namespace(self.ptr).decode('utf-8')

    @functools.cached_property
    def fields(self) -> tuple[MonoField, ...]:
        api = MonoApi.get_instance()
        it = ctypes.c_size_t(0)
        res = []
        while field := api.mono_class_get_fields(self.ptr, ctypes.byref(it)):
            res.append(MonoField(field))
        return tuple(res)

    @functools.cached_property
    def implemented_interfaces(self) -> tuple:
        api = MonoApi.get_instance()
        it = ctypes.c_size_t(0)
        res = []
        while interface := api.mono_class_get_interfaces(self.ptr, ctypes.byref(it)):
            res.append(interface)
        return tuple(res)

    @functools.cached_property
    def methods(self) -> tuple[MonoMethod, ...]:
        api = MonoApi.get_instance()
        it = ctypes.c_size_t(0)
        res = []
        while method := api.mono_class_get_methods(self.ptr, ctypes.byref(it)):
            res.append(MonoMethod(method))
        return tuple(res)

    def find_method(self, methodname: str, param_count: int = -1) -> MonoMethod | None:
        return MonoMethod(MonoApi.get_instance().mono_class_get_method_from_name(
            self.ptr, methodname.encode('utf-8'), param_count
        ))


class MonoJitInfo(_MonoObj):
    @functools.cached_property
    def method(self):
        return MonoMethod(MonoApi.get_instance().mono_jit_info_get_method(self.ptr))

    @functools.cached_property
    def code_start(self):
        return MonoApi.get_instance().mono_jit_info_get_code_start(self.ptr)

    @functools.cached_property
    def code_size(self):
        return MonoApi.get_instance().mono_jit_info_get_code_size(self.ptr)


class MonoDomain(_MonoObj):
    def set(self):
        api = MonoApi.get_instance()
        return api.mono_domain_set(self.ptr, False) if not api.mono_domain_set else 0

    def get_jit_info(self, address):
        return MonoJitInfo(MonoApi.get_instance().mono_jit_info_table_find(self.ptr, address))


class MonoAssembly(_MonoObj):
    @functools.cached_property
    def image(self):
        return MonoImage(MonoApi.get_instance().mono_assembly_get_image(self.ptr))


class MonoImage(_MonoObj):
    @functools.cached_property
    def name(self) -> str:
        return MonoApi.get_instance().mono_image_get_name(self.ptr).decode('utf-8')

    @functools.cached_property
    def filename(self) -> str:
        return MonoApi.get_instance().mono_image_get_filename(self.ptr).decode('utf-8')

    def get_rva_map(self, i):
        return MonoApi.get_instance().mono_image_rva_map(self.ptr, i)

    @functools.cached_property
    def clss(self) -> tuple[MonoClass, ...]:
        api = MonoApi.get_instance()
        res = []
        if api.is_il2cpp:
            for i in range(api.il2cpp_image_get_class_count(self.ptr)):
                res.append(MonoClass(api.il2cpp_image_get_class(self.ptr, i)))
        else:
            tdef = api.mono_image_get_table_info(self.ptr, MonoMetaTableEnum.TYPEDEF)
            for i in range(api.mono_table_info_get_rows(tdef)):
                res.append(MonoClass(api.mono_class_get(self.ptr, MonoTokenType.TYPE_DEF | (i + 1))))
        return tuple(res)

    def find_class(self, classname: str, namespace: str = '') -> MonoClass | None:
        api = MonoApi.get_instance()
        return MonoClass((api.mono_class_from_name_case or api.mono_class_from_name)(
            self.ptr, namespace.encode('utf-8'), classname.encode('utf-8')
        ))


class Mono:
    instance: 'Mono'

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = cls()
        return cls.instance

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self, mono_handle=None, is_il2cpp=False):
        if hasattr(self, 'api'):  return
        self.api = MonoApi(mono_handle, is_il2cpp)
        self.is_il2cpp = self.api.is_il2cpp
        self.domain = self.api.mono_get_root_domain()

        self.mono_selfthread = None
        self.is_attached = False
        self.uwp_mode = False

        self.connect_thread_to_mono_runtime()

    def connect_thread_to_mono_runtime(self):
        self.mono_selfthread = None
        if self.api.mono_thread_attach and self.api.mono_domain_get:
            self.mono_selfthread = self.api.mono_thread_attach(self.api.mono_get_root_domain())
        self.is_attached = bool(self.mono_selfthread)

    @functools.cached_property
    def domains(self) -> tuple[MonoDomain, ...]:
        if self.is_il2cpp:
            return MonoDomain(self.api.mono_domain_get()),
        domains = []
        c_iterator = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(lambda domain: domains.append(MonoDomain(domain)))
        self.api.mono_domain_foreach(c_iterator)
        return tuple(domains)

    @functools.cached_property
    def assemblies(self) -> tuple[MonoAssembly, ...]:
        res = []
        if self.is_il2cpp:
            ptr = self.api.il2cpp_domain_get_assemblies(self.api.mono_domain_get(), ctypes.byref(cnt := ctypes.c_size_t()))
            for i in range(cnt.value):
                res.append(MonoAssembly(ptr[i]))
        else:
            c_iterator = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(lambda assembly: res.append(MonoAssembly(assembly)))
            self.api.mono_assembly_foreach(c_iterator, None)
        return tuple(res)
