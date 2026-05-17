#pragma once

#include "gHeader.h"

namespace mNameSpace { namespace PyImguiCore {

struct PyOwnedMemory
{
    uintptr_t address = 0;
    std::shared_ptr<void> owner;
};

struct PyMemoryTypeInfo
{
    std::string type_name = "void";
    size_t item_size = 0;
    size_t flat_item_size = 0;
    bool python_item_is_pointer = false;
    std::function<py::object(uintptr_t, py::ssize_t)> get_item;
    std::function<void(uintptr_t, py::ssize_t, py::object)> set_item;
    std::function<py::object(uintptr_t, py::ssize_t)> get_flat_item;
    std::function<void(uintptr_t, py::ssize_t, py::object)> set_flat_item;
    std::function<PyOwnedMemory(size_t)> allocate_item;
    std::function<PyOwnedMemory(size_t)> allocate_flat;
};

static uintptr_t pyimgui_address_from_object(py::object value);

template <typename T>
static T* pyimgui_ptr_from_object(py::object value);

static bool pyimgui_is_sequence_argument(py::object value)
{
    return !value.is_none()
        && !py::isinstance<py::str>(value)
        && !py::isinstance<py::bytes>(value)
        && !PyByteArray_Check(value.ptr())
        && py::isinstance<py::sequence>(value);
}

struct PyImVectorBase
{
    virtual ~PyImVectorBase() = default;
};

template <typename T>
static py::class_<T> pyimgui_add_default_init(py::class_<T> cls)
{
    if constexpr (std::is_default_constructible_v<T>)
    {
        cls.def(py::init([]() { return new T(); }));
    }
    return cls;
}

template <typename T>
struct PyImVectorWrapper : PyImVectorBase
{
    ImVector<T>* vector = nullptr;
    std::shared_ptr<ImVector<T>> owner;

    PyImVectorWrapper()
        : vector(nullptr), owner(std::make_shared<ImVector<T>>())
    {
        this->vector = this->owner.get();
    }

    PyImVectorWrapper(ImVector<T>* vector)
        : vector(vector)
    {
    }

    py::object get(size_t index) const
    {
        if (!this->vector || index >= (size_t)this->vector->Size)
            _throwV_("Index out of range: {}", index);
        auto& value = (*this->vector)[(int)index];
        if constexpr (std::is_pointer_v<T>)
            return py::cast(value, py::return_value_policy::reference);
        else if constexpr (std::is_class_v<T> || std::is_union_v<T>)
            return py::cast(&value, py::return_value_policy::reference);
        else
            return py::cast(value);
    }

    void set(size_t index, py::object value)
    {
        if (!this->vector || index >= (size_t)this->vector->Size)
            _throwV_("Index out of range: {}", index);
        (*this->vector)[(int)index] = cast_value(value);
    }

    size_t size() const
    {
        return this->vector ? (size_t)this->vector->Size : 0;
    }

    size_t capacity() const
    {
        return this->vector ? (size_t)this->vector->Capacity : 0;
    }

    void clear()
    {
        if (this->vector)
            this->vector->clear();
    }

    void append(py::object value)
    {
        if (!this->vector)
            _throw_("ImVector wrapper is not attached");
        this->vector->push_back(cast_value(value));
    }

    static T cast_value(py::object value)
    {
        if constexpr (std::is_pointer_v<T>)
        {
            using Pointee = std::remove_pointer_t<T>;
            return reinterpret_cast<T>(pyimgui_ptr_from_object<std::remove_const_t<Pointee>>(value));
        }
        else if constexpr (std::is_class_v<T> || std::is_union_v<T>)
        {
            auto* ptr = pyimgui_ptr_from_object<T>(value);
            if (!ptr)
                _throw_("ImVector record item cannot be None");
            return *ptr;
        }
        else
        {
            return value.cast<T>();
        }
    }

    static void pybind_setup(py::module_ m, const char* name)
    {
        auto cls = py::class_<PyImVectorWrapper<T>, PyImVectorBase>(m, name, py::dynamic_attr())
            .def(py::init<>())
            .def_property_readonly("Size", &PyImVectorWrapper<T>::size)
            .def_property_readonly("Capacity", &PyImVectorWrapper<T>::capacity)
            .def("__len__", &PyImVectorWrapper<T>::size)
            .def("__getitem__", &PyImVectorWrapper<T>::get)
            .def("clear", &PyImVectorWrapper<T>::clear);
        if constexpr (std::is_pointer_v<T> || !(std::is_class_v<T> || std::is_union_v<T>) || std::is_copy_assignable_v<T>)
            cls.def("__setitem__", &PyImVectorWrapper<T>::set);
        if constexpr (std::is_pointer_v<T> || !(std::is_class_v<T> || std::is_union_v<T>) || std::is_copy_constructible_v<T>)
            cls.def("append", &PyImVectorWrapper<T>::append);
    }
};

static std::shared_ptr<PyMemoryTypeInfo> pyimgui_void_memory_type()
{
    static auto info = []() {
        auto type_info = std::make_shared<PyMemoryTypeInfo>();
        type_info->get_item = [](uintptr_t, py::ssize_t) -> py::object { _throw_("Pointer type is void"); return py::none(); };
        type_info->set_item = [](uintptr_t, py::ssize_t, py::object) { _throw_("Pointer type is void"); };
        type_info->get_flat_item = type_info->get_item;
        type_info->set_flat_item = type_info->set_item;
        type_info->allocate_item = [](size_t) -> PyOwnedMemory { _throw_("Cannot allocate Pointer[void]"); return {}; };
        type_info->allocate_flat = [](size_t) -> PyOwnedMemory { _throw_("Cannot allocate ArrayFlat[void]"); return {}; };
        return type_info;
    }();
    return info;
}

static std::shared_ptr<PyMemoryTypeInfo> pyimgui_make_raw_memory_type(const char* type_name, size_t item_size, size_t flat_item_size, bool python_item_is_pointer, bool read_only = false)
{
    auto info = std::make_shared<PyMemoryTypeInfo>();
    info->type_name = type_name;
    info->item_size = item_size;
    info->flat_item_size = flat_item_size;
    info->python_item_is_pointer = python_item_is_pointer;
    info->get_item = [](uintptr_t, py::ssize_t) -> py::object { _throw_("Direct content access is not supported for this internal record pointer"); return py::none(); };
    info->set_item = read_only
        ? std::function<void(uintptr_t, py::ssize_t, py::object)>([](uintptr_t, py::ssize_t, py::object) { _throw_("Memory view is read-only"); })
        : std::function<void(uintptr_t, py::ssize_t, py::object)>([](uintptr_t, py::ssize_t, py::object) { _throw_("Direct content assignment is not supported for this internal record pointer"); });
    info->get_flat_item = info->get_item;
    info->set_flat_item = info->set_item;
    info->allocate_item = [](size_t) -> PyOwnedMemory { _throw_("Cannot allocate raw internal record memory"); return {}; };
    info->allocate_flat = info->allocate_item;
    return info;
}

static std::unordered_map<std::string, std::shared_ptr<PyMemoryTypeInfo>>& pyimgui_memory_type_registry()
{
    static std::unordered_map<std::string, std::shared_ptr<PyMemoryTypeInfo>> registry;
    return registry;
}

static std::string pyimgui_memory_type_key(py::object type_arg)
{
    if (py::isinstance<py::str>(type_arg))
        return type_arg.cast<std::string>();
    if (py::hasattr(type_arg, "__name__"))
        return type_arg.attr("__name__").cast<std::string>();
    _throw_("Expected a pyimgui class or type name");
}

static void pyimgui_register_memory_type(py::object type_arg, std::shared_ptr<PyMemoryTypeInfo> info)
{
    pyimgui_memory_type_registry()[pyimgui_memory_type_key(type_arg)] = std::move(info);
}

static std::shared_ptr<PyMemoryTypeInfo> pyimgui_memory_type_for(py::object type_arg)
{
    auto key = pyimgui_memory_type_key(type_arg);
    auto& registry = pyimgui_memory_type_registry();
    auto it = registry.find(key);
    if (it == registry.end())
        _throwV_("Unsupported Pointer/ArrayFlat item type: {}", key);
    return it->second;
}

struct PyPointer
{
    uintptr_t address = 0;
    std::shared_ptr<PyMemoryTypeInfo> type_info = pyimgui_void_memory_type();
    size_t count = 0;
    std::shared_ptr<void> owner;

    PyPointer() = default;

    PyPointer(uintptr_t address, std::shared_ptr<PyMemoryTypeInfo> type_info, size_t count = 0, std::shared_ptr<void> owner = {})
        : address(address), type_info(std::move(type_info)), count(count), owner(std::move(owner))
    {
    }

    std::string type_name() const
    {
        return this->type_info ? this->type_info->type_name : "void";
    }

    size_t item_size() const
    {
        return this->type_info ? this->type_info->item_size : 0;
    }

    explicit operator bool() const
    {
        return this->address != 0;
    }

    py::object get(py::ssize_t index) const
    {
        if (!this->address)
            _throw_("Pointer is null");
        if (index < 0)
            _throwV_("Negative pointer index: {}", index);
        if (this->count && (size_t)index >= this->count)
            _throwV_("Pointer index out of range: {}", index);
        return this->type_info->get_item(this->address, index);
    }

    void set(py::ssize_t index, py::object value) const
    {
        if (!this->address)
            _throw_("Pointer is null");
        if (index < 0)
            _throwV_("Negative pointer index: {}", index);
        if (this->count && (size_t)index >= this->count)
            _throwV_("Pointer index out of range: {}", index);
        this->type_info->set_item(this->address, index, value);
    }

    py::object content() const
    {
        return this->get(0);
    }

    void set_content(py::object value) const
    {
        this->set(0, value);
    }

    py::object getattr(const char* name) const
    {
        return this->content().attr(name);
    }

    std::string repr() const
    {
        return std::format("Pointer[{}](0x{:X})", this->type_name(), this->address);
    }
};

struct PyArray : PyPointer
{
    size_t length = 0;

    PyArray() = default;

    PyArray(uintptr_t address, std::shared_ptr<PyMemoryTypeInfo> type_info, size_t length, std::shared_ptr<void> owner = {})
        : PyPointer(address, std::move(type_info), length, std::move(owner)), length(length)
    {
    }

    py::object get_checked(py::ssize_t index) const
    {
        if (index < 0 || (size_t)index >= this->length)
            _throwV_("Array index out of range: {}", index);
        return this->get(index);
    }

    void set_checked(py::ssize_t index, py::object value) const
    {
        if (index < 0 || (size_t)index >= this->length)
            _throwV_("Array index out of range: {}", index);
        this->set(index, value);
    }

    std::string repr() const
    {
        return std::format("Array[{}](0x{:X}, {})", this->type_name(), this->address, this->length);
    }
};

struct PyArrayFlat
{
    uintptr_t address = 0;
    std::shared_ptr<PyMemoryTypeInfo> type_info = pyimgui_void_memory_type();
    size_t length = 0;
    std::shared_ptr<void> owner;

    PyArrayFlat() = default;

    PyArrayFlat(uintptr_t address, std::shared_ptr<PyMemoryTypeInfo> type_info, size_t length, std::shared_ptr<void> owner = {})
        : address(address), type_info(std::move(type_info)), length(length), owner(std::move(owner))
    {
    }

    std::string type_name() const
    {
        return this->type_info ? this->type_info->type_name : "void";
    }

    size_t item_size() const
    {
        return this->type_info ? this->type_info->flat_item_size : 0;
    }

    py::object get_checked(py::ssize_t index) const
    {
        if (!this->address)
            _throw_("ArrayFlat is null");
        if (index < 0 || (size_t)index >= this->length)
            _throwV_("ArrayFlat index out of range: {}", index);
        return this->type_info->get_flat_item(this->address, index);
    }

    void set_checked(py::ssize_t index, py::object value) const
    {
        if (!this->address)
            _throw_("ArrayFlat is null");
        if (index < 0 || (size_t)index >= this->length)
            _throwV_("ArrayFlat index out of range: {}", index);
        this->type_info->set_flat_item(this->address, index, value);
    }

    explicit operator bool() const
    {
        return this->address != 0;
    }

    std::string repr() const
    {
        return std::format("ArrayFlat[{}](0x{:X}, {})", this->type_name(), this->address, this->length);
    }
};

struct PyPointerFactory
{
    std::shared_ptr<PyMemoryTypeInfo> type_info;

    PyPointerFactory(std::shared_ptr<PyMemoryTypeInfo> type_info)
        : type_info(std::move(type_info))
    {
    }

    PyPointer create(py::object address, size_t count) const
    {
        uintptr_t raw_address = address.is_none() ? 0 : pyimgui_address_from_object(address);
        std::shared_ptr<void> owner;
        if (!raw_address && count)
        {
            auto memory = this->type_info->allocate_item(count);
            raw_address = memory.address;
            owner = std::move(memory.owner);
        }
        return PyPointer(raw_address, this->type_info, count, std::move(owner));
    }
};

struct PyArrayFactory
{
    std::shared_ptr<PyMemoryTypeInfo> type_info;

    PyArrayFactory(std::shared_ptr<PyMemoryTypeInfo> type_info)
        : type_info(std::move(type_info))
    {
    }

    PyArray create(py::object address, size_t count) const
    {
        uintptr_t raw_address = address.is_none() ? 0 : pyimgui_address_from_object(address);
        std::shared_ptr<void> owner;
        if (!raw_address && count)
        {
            auto memory = this->type_info->allocate_item(count);
            raw_address = memory.address;
            owner = std::move(memory.owner);
        }
        return PyArray(raw_address, this->type_info, count, std::move(owner));
    }
};

struct PyArrayFlatFactory
{
    std::shared_ptr<PyMemoryTypeInfo> type_info;

    PyArrayFlatFactory(std::shared_ptr<PyMemoryTypeInfo> type_info)
        : type_info(std::move(type_info))
    {
    }

    PyArrayFlat create(py::object address, size_t count) const
    {
        uintptr_t raw_address = address.is_none() ? 0 : pyimgui_address_from_object(address);
        std::shared_ptr<void> owner;
        if (!raw_address && count)
        {
            auto memory = this->type_info->allocate_flat(count);
            raw_address = memory.address;
            owner = std::move(memory.owner);
        }
        return PyArrayFlat(raw_address, this->type_info, count, std::move(owner));
    }
};

static uintptr_t pyimgui_address_from_object(py::object value)
{
    if (value.is_none())
        return 0;
    if (py::isinstance<PyPointer>(value))
        return value.cast<PyPointer&>().address;
    if (py::isinstance<PyArrayFlat>(value))
        return value.cast<PyArrayFlat&>().address;
    if (py::isinstance<py::int_>(value))
        return value.cast<uintptr_t>();
    try
    {
        auto ctypes = py::module_::import("ctypes");
        try
        {
            return ctypes.attr("addressof")(value).cast<uintptr_t>();
        }
        catch (const py::error_already_set&)
        {
            if (py::hasattr(value, "contents"))
                return ctypes.attr("addressof")(value.attr("contents")).cast<uintptr_t>();
        }
    }
    catch (const py::error_already_set&)
    {
    }
    _throw_("Expected Pointer, Array, ArrayFlat, ctypes object, integer address, or None");
}

template <typename T>
static T* pyimgui_ptr_from_object(py::object value)
{
    if (value.is_none())
        return nullptr;
    try
    {
        return value.cast<T*>();
    }
    catch (const py::cast_error&)
    {
    }
    if (py::isinstance<PyArrayFlat>(value))
        return reinterpret_cast<T*>(value.cast<PyArrayFlat&>().address);
    if (py::isinstance<PyPointer>(value))
    {
        auto& pointer = value.cast<PyPointer&>();
        if (pointer.type_info && pointer.type_info->python_item_is_pointer)
        {
            if (!pointer.address)
                return nullptr;
            return reinterpret_cast<T**>(pointer.address)[0];
        }
    }
    if (py::isinstance<PyArray>(value))
    {
        auto& array = value.cast<PyArray&>();
        if (array.type_info && array.type_info->python_item_is_pointer)
        {
            if (!array.address || !array.length)
                return nullptr;
            return reinterpret_cast<T**>(array.address)[0];
        }
    }
    return reinterpret_cast<T*>(pyimgui_address_from_object(value));
}

template <typename T>
static PyOwnedMemory pyimgui_allocate_pointer_slots(size_t count)
{
    auto data = new T*[count]();
    return PyOwnedMemory{
        reinterpret_cast<uintptr_t>(data),
        std::shared_ptr<void>(data, [](void* ptr) { delete[] static_cast<T**>(ptr); }),
    };
}

template <typename T, bool AllowFlatCopy>
static PyOwnedMemory pyimgui_allocate_value_items(size_t count)
{
    if constexpr (!(std::is_class_v<T> || std::is_union_v<T>) || AllowFlatCopy)
    {
        auto data = static_cast<T*>(::operator new[](sizeof(T) * count));
        std::memset(data, 0, sizeof(T) * count);
        return PyOwnedMemory{
            reinterpret_cast<uintptr_t>(data),
            std::shared_ptr<void>(data, [](void* ptr) { ::operator delete[](ptr); }),
        };
    }
    else
    {
        _throw_("Allocation requires a flat-copyable value type");
    }
    return {};
}

template <typename T, bool AllowPyCast>
static py::object pyimgui_get_flat_item(uintptr_t address, py::ssize_t index)
{
    if constexpr (std::is_class_v<T> || std::is_union_v<T>)
    {
        if constexpr (AllowPyCast)
        {
            return py::cast(reinterpret_cast<T*>(address) + index, py::return_value_policy::reference);
        }
        else
        {
            _throw_("Direct content access is not supported for this internal record pointer");
            return py::none();
        }
    }
    else if constexpr (std::is_enum_v<T>)
    {
        return py::int_((long long)(reinterpret_cast<T*>(address)[index]));
    }
    else
    {
        return py::cast(reinterpret_cast<T*>(address)[index]);
    }
}

template <typename T, bool AllowFlatCopy, bool AllowPyCast>
static void pyimgui_set_flat_item(uintptr_t address, py::ssize_t index, py::object value)
{
    if constexpr (std::is_class_v<T> || std::is_union_v<T>)
    {
        if constexpr (AllowFlatCopy && AllowPyCast)
        {
            auto source = pyimgui_ptr_from_object<T>(value);
            if (!source)
                _throw_("Cannot assign None to a flat object array element");
            std::memcpy(reinterpret_cast<T*>(address) + index, source, sizeof(T));
        }
        else
        {
            _throw_("Flat object array assignment requires a flat-copyable type");
        }
    }
    else if constexpr (std::is_enum_v<T>)
    {
        reinterpret_cast<T*>(address)[index] = static_cast<T>(value.cast<long long>());
    }
    else
    {
        reinterpret_cast<T*>(address)[index] = value.cast<T>();
    }
}

template <typename T, bool AllowPyCast>
static py::object pyimgui_get_pointer_item(uintptr_t address, py::ssize_t index)
{
    if constexpr (!AllowPyCast)
    {
        _throw_("Direct content access is not supported for this internal record pointer");
        return py::none();
    }
    auto item = reinterpret_cast<T**>(address)[index];
    if (!item)
        return py::none();
    return py::cast(item, py::return_value_policy::reference);
}

template <typename T, bool AllowPyCast>
static void pyimgui_set_pointer_item(uintptr_t address, py::ssize_t index, py::object value)
{
    if constexpr (!AllowPyCast)
    {
        _throw_("Direct content assignment is not supported for this internal record pointer");
        return;
    }
    reinterpret_cast<T**>(address)[index] = pyimgui_ptr_from_object<T>(value);
}

template <typename T, bool PythonItemIsPointer, bool AllowFlatCopy = false, bool AllowPyCast = true>
static std::shared_ptr<PyMemoryTypeInfo> pyimgui_make_memory_type(const char* type_name, bool read_only = false)
{
    auto info = std::make_shared<PyMemoryTypeInfo>();
    info->type_name = type_name;
    info->python_item_is_pointer = PythonItemIsPointer;
    info->item_size = PythonItemIsPointer ? sizeof(T*) : sizeof(T);
    info->flat_item_size = sizeof(T);
    info->get_flat_item = &pyimgui_get_flat_item<T, AllowPyCast>;
    info->set_flat_item = read_only
        ? std::function<void(uintptr_t, py::ssize_t, py::object)>([](uintptr_t, py::ssize_t, py::object) { _throw_("Memory view is read-only"); })
        : &pyimgui_set_flat_item<T, AllowFlatCopy, AllowPyCast>;
    if constexpr (PythonItemIsPointer)
    {
        info->get_item = &pyimgui_get_pointer_item<T, AllowPyCast>;
        info->set_item = read_only
            ? std::function<void(uintptr_t, py::ssize_t, py::object)>([](uintptr_t, py::ssize_t, py::object) { _throw_("Memory view is read-only"); })
            : &pyimgui_set_pointer_item<T, AllowPyCast>;
        info->allocate_item = [](size_t count) { return pyimgui_allocate_pointer_slots<T>(count); };
    }
    else
    {
        info->get_item = info->get_flat_item;
        info->set_item = info->set_flat_item;
        info->allocate_item = [](size_t count) { return pyimgui_allocate_value_items<T, AllowFlatCopy>(count); };
    }
    info->allocate_flat = [](size_t count) { return pyimgui_allocate_value_items<T, AllowFlatCopy>(count); };
    return info;
}

template <typename T>
struct PyInputValueArray
{
    T* pointer = nullptr;
    std::vector<T> storage;

    T* get() const
    {
        return this->pointer;
    }
};

template <typename T>
static T pyimgui_sequence_item_to_value(py::object value)
{
    if constexpr (std::is_class_v<T> || std::is_union_v<T>)
    {
        if constexpr (std::is_copy_constructible_v<T>)
        {
            auto* ptr = pyimgui_ptr_from_object<T>(value);
            if (!ptr)
                _throw_("Sequence record item cannot be None");
            return *ptr;
        }
        else
        {
            _throw_("Sequence conversion requires a copy-constructible record type");
            return T{};
        }
    }
    else if constexpr (std::is_enum_v<T>)
    {
        return static_cast<T>(value.cast<long long>());
    }
    else
    {
        return value.cast<T>();
    }
}

template <typename T>
static PyInputValueArray<T> pyimgui_input_value_array_from_object(py::object value)
{
    PyInputValueArray<T> result;
    if (value.is_none())
        return result;
    if (pyimgui_is_sequence_argument(value))
    {
        py::sequence sequence = value.cast<py::sequence>();
        result.storage.reserve((size_t)sequence.size());
        for (size_t i = 0; i < (size_t)sequence.size(); ++i)
            result.storage.push_back(pyimgui_sequence_item_to_value<T>(py::reinterpret_borrow<py::object>(sequence[(py::ssize_t)i])));
        result.pointer = result.storage.empty() ? nullptr : result.storage.data();
        return result;
    }
    if constexpr (std::is_class_v<T> || std::is_union_v<T>)
        result.pointer = pyimgui_ptr_from_object<T>(value);
    else
        result.pointer = reinterpret_cast<T*>(pyimgui_address_from_object(value));
    return result;
}

template <typename T>
struct PyInputPointerArray
{
    T** pointer = nullptr;
    std::vector<T*> storage;

    T** get() const
    {
        return this->pointer;
    }
};

template <typename T>
static PyInputPointerArray<T> pyimgui_input_pointer_array_from_object(py::object value)
{
    PyInputPointerArray<T> result;
    if (value.is_none())
        return result;
    if (pyimgui_is_sequence_argument(value))
    {
        py::sequence sequence = value.cast<py::sequence>();
        result.storage.reserve((size_t)sequence.size());
        for (size_t i = 0; i < (size_t)sequence.size(); ++i)
            result.storage.push_back(pyimgui_ptr_from_object<T>(py::reinterpret_borrow<py::object>(sequence[(py::ssize_t)i])));
        result.pointer = result.storage.empty() ? nullptr : result.storage.data();
        return result;
    }
    result.pointer = reinterpret_cast<T**>(pyimgui_address_from_object(value));
    return result;
}

static void pyimgui_setup_runtime(py::module_ m)
{
    py::class_<PyPointerFactory>(m, "_PointerFactory")
        .def("__call__", &PyPointerFactory::create, py::arg("address") = py::none(), py::arg("count") = 0);

    py::class_<PyArrayFactory>(m, "_ArrayFactory")
        .def("__call__", &PyArrayFactory::create, py::arg("address") = py::none(), py::arg("count") = 0);

    py::class_<PyArrayFlatFactory>(m, "_ArrayFlatFactory")
        .def("__call__", &PyArrayFlatFactory::create, py::arg("address") = py::none(), py::arg("count") = 0);

    pyimgui_register_memory_type(py::str("bool"), pyimgui_make_memory_type<bool, false, true, true>("bool"));
    pyimgui_register_memory_type(py::str("int"), pyimgui_make_memory_type<int, false, true, true>("int"));
    pyimgui_register_memory_type(py::str("float"), pyimgui_make_memory_type<float, false, true, true>("float"));
    pyimgui_register_memory_type(py::str("double"), pyimgui_make_memory_type<double, false, true, true>("double"));

    py::class_<PyPointer>(m, "Pointer", py::dynamic_attr())
        .def(py::init<>())
        .def(py::init([](py::object address) { return PyPointer(pyimgui_address_from_object(address), pyimgui_void_memory_type()); }), py::arg("address"))
        .def_property_readonly("address", [](const PyPointer& self) { return py::int_(self.address); })
        .def_property_readonly("type_name", &PyPointer::type_name)
        .def_property_readonly("item_size", &PyPointer::item_size)
        .def_readonly("count", &PyPointer::count)
        .def_property("content", &PyPointer::content, &PyPointer::set_content)
        .def("__bool__", [](const PyPointer& self) { return (bool)self; })
        .def("__getitem__", &PyPointer::get)
        .def("__setitem__", &PyPointer::set)
        .def("__getattr__", &PyPointer::getattr)
        .def("__repr__", &PyPointer::repr)
        .def_static("__class_getitem__", [](py::object item) { return PyPointerFactory(pyimgui_memory_type_for(item)); });

    py::class_<PyArray, PyPointer>(m, "Array", py::dynamic_attr())
        .def_readonly("length", &PyArray::length)
        .def("__len__", [](const PyArray& self) { return self.length; })
        .def("__getitem__", &PyArray::get_checked)
        .def("__setitem__", &PyArray::set_checked)
        .def("__repr__", &PyArray::repr)
        .def_static("__class_getitem__", [](py::object item) { return PyArrayFactory(pyimgui_memory_type_for(item)); });

    py::class_<PyArrayFlat>(m, "ArrayFlat", py::dynamic_attr())
        .def(py::init<>())
        .def_property_readonly("address", [](const PyArrayFlat& self) { return py::int_(self.address); })
        .def_property_readonly("type_name", &PyArrayFlat::type_name)
        .def_property_readonly("item_size", &PyArrayFlat::item_size)
        .def_readonly("length", &PyArrayFlat::length)
        .def("__bool__", [](const PyArrayFlat& self) { return (bool)self; })
        .def("__len__", [](const PyArrayFlat& self) { return self.length; })
        .def("__getitem__", &PyArrayFlat::get_checked)
        .def("__setitem__", &PyArrayFlat::set_checked)
        .def("__repr__", &PyArrayFlat::repr)
        .def_static("__class_getitem__", [](py::object item) { return PyArrayFlatFactory(pyimgui_memory_type_for(item)); });
}

}}