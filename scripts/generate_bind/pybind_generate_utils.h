#pragma once
#include <type_traits>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <pybind11/complex.h>
#include <pybind11/chrono.h>

namespace py = pybind11;

namespace NY_BIND
{

    bool is_defined(py::module &m, const std::string &className)
    {
        try
        {
            return py::isinstance<py::type>(m.attr(className.c_str()));
        }
        catch (const py::error_already_set &)
        {
            return false;
        }
    }

    template <typename T>
    class PointerWrapper
    {
    public:
        PointerWrapper() : m_ptr(nullptr) {}
        PointerWrapper(T *ptr) : m_ptr(ptr) {}
        PointerWrapper(size_t addr) : m_ptr(reinterpret_cast<T *>(addr)) {}

        PointerWrapper(const PointerWrapper &other) : m_ptr(other.m_ptr) {}

        PointerWrapper &operator=(const PointerWrapper &other)
        {
            if (this != &other)
            {
                m_ptr = other.m_ptr;
            }
            return *this;
        }

        T *get() const { return m_ptr; }

        PointerWrapper<T> add(int offset) const
        {
            return PointerWrapper<T>(m_ptr + offset);
        }

        PointerWrapper<T> sub(int offset) const
        {
            return PointerWrapper<T>(m_ptr - offset);
        }

        T &getitem(int index) const
        {
            return m_ptr[index];
        }

        void setitem(int index, const T &value)
        {
            m_ptr[index] = value;
        }

        operator size_t() const
        {
            return reinterpret_cast<size_t>(m_ptr);
        }

        static void bind(py::module &m)
        {
            std::string name = "PointerWrapper__" + std::string(typeid(T).name());
            if (is_defined(m, name))
                return;
            py::class_<PointerWrapper<T>>(m, name.c_str())
                .def(py::init<>())
                .def(py::init<size_t>())
                .def(py::init<const PointerWrapper<T> &>())
                .def("__add__", &PointerWrapper<T>::add)
                .def("__sub__", &PointerWrapper<T>::sub)
                .def("__getitem__", &PointerWrapper<T>::getitem)
                .def("__setitem__", &PointerWrapper<T>::setitem)
                .def("__int__", [](const PointerWrapper<T> &pw)
                     { return static_cast<size_t>(pw); });
        }

    private:
        T *m_ptr;
    };

    template <typename T>
    void SetPointer(T **ptr, const py::object &obj)
    {
        if (obj.is_none())
        {
            *ptr = nullptr;
            return;
        }
        if (py::isinstance<py::int_>(obj))
        {
            *ptr = (T *)obj.cast<size_t>();
            return;
        }
        if (py::isinstance<PointerWrapper<T>>(obj))
        {
            *ptr = obj.cast<PointerWrapper<T>>().get();
            return;
        }
        throw std::runtime_error("Invalid object type");
    }

    template <typename T>
    class ArrayWrapper
    {
    private:
        T *m_ptr;
        size_t m_size;

    public:
        ArrayWrapper(T *ptr, size_t size) : m_ptr(ptr), m_size(size) {}

        T *get() const { return m_ptr; }
        size_t size() const { return m_size; }

        T &getitem(int index) const
        {
            return m_ptr[index];
        }

        void setitem(int index, const T &value)
        {
            m_ptr[index] = value;
        }

        static void bind(py::module &m)
        {
            std::string name = "ArrayWrapper__" + std::string(typeid(T).name());
            if (is_defined(m, name))
                return;
            py::class_<ArrayWrapper<T>>(m, name.c_str())
                .def("__getitem__", &ArrayWrapper<T>::getitem)
                .def("__setitem__", &ArrayWrapper<T>::setitem)
                .def("__len__", &ArrayWrapper<T>::size)
                .def("__iter__", [](const ArrayWrapper<T> &aw)
                     { return py::make_iterator(aw.get(), aw.get() + aw.size()); }, py::keep_alive<0, 1>());
        }
    };

    template <typename T>
    void SetArray(T *ptr, const py::object &obj, size_t size)
    {
        py::iterator it = py::iter(obj);
        size_t i = 0;
        while (i < size)
        {
            try
            {
                ptr[i] = it.attr("__next__")().cast<T>();
                ++i;
            }
            catch (const py::stop_iteration &)
            {
                break;
            }
        }
    }

    template <typename T>
    struct array_element_type
    {
        using type = T;
    };
    template <typename T, size_t N>
    struct array_element_type<T[N]>
    {
        using type = T;
    };
    template <typename T>
    using array_element_type_t = typename array_element_type<T>::type;

    void set_char_p(char **dest, py::object obj)
    {
        if (obj.is_none())
        {
            *dest = nullptr;
            return;
        }
        if (py::isinstance<py::int_>(obj))
        {
            *dest = (char *)obj.cast<size_t>();
            return;
        }
        throw std::runtime_error("Invalid object type");
    }

    void set_char_arr(char *dest, const py::bytes &str, size_t size)
    {
        char *buffer;
        size_t length;
        if (PYBIND11_BYTES_AS_STRING_AND_SIZE(str.ptr(), &buffer, (Py_ssize_t *)(&length)))
            throw py::error_already_set();
        length = std::min(length, size);
        strncpy(dest, buffer, length);
        if (length < size)
        {
            dest[length] = '\0';
        }
    }

    // Helper type trait to get field type from a member pointer

    template <typename T>
    struct class_of_member_pointer;
    template <typename Class, typename Field>
    struct class_of_member_pointer<Field Class::*>
    {
        using type = Class;
    };
    template <auto FieldPtr>
    using class_type = typename class_of_member_pointer<decltype(FieldPtr)>::type;
    template <typename Class, auto Field>
    using field_type = std::remove_reference_t<decltype(std::declval<Class>().*Field)>;
    template <typename T, typename V>
    auto make_optional(V &&v)
    {
        return v ? std::optional(T(v)) : std::nullopt;
    }

    template <auto Field>
    void def_pointer(py::class_<class_type<Field>> &c, const char *name)
    {
        using Class = class_type<Field>;
        using PointedType = std::remove_pointer_t<field_type<Class, Field>>;
        c.def_property(name, [](const Class &self)
                       { return make_optional<NY_BIND::PointerWrapper<PointedType>>(self.*Field); }, [](Class &self, const py::object &ptr)
                       { NY_BIND::SetPointer(&(self.*Field), ptr); });
    }

    template <auto Field>
    void def_array(py::class_<class_type<Field>> &c, const char *name)
    {
        using Class = class_type<Field>;
        using ArrayType = field_type<Class, Field>;
        using ElementType = NY_BIND::array_element_type_t<ArrayType>;
        constexpr size_t Count = sizeof(ArrayType) / sizeof(ElementType);

        c.def_property(name, [](const Class &self)
                       { return NY_BIND::ArrayWrapper<ElementType>((ElementType *)(self.*Field), Count); }, [](Class &self, const py::object &obj)
                       { NY_BIND::SetArray(self.*Field, obj, Count); });
    }

    template <auto Field>
    void def_c_func(py::class_<class_type<Field>> &c, const char *name)
    {
        using Class = class_type<Field>;
        using FieldType = field_type<Class, Field>;
        using FuncType = std::remove_pointer_t<FieldType>;
        c.def_property(
            name,
            [](const Class &self)
            { return std::function<FuncType>(self.*Field); },
            [](Class &self, std::optional<size_t> func_ptr)
            { (self.*Field) = (func_ptr ? (FieldType)(*func_ptr) : nullptr); });
    }
}

#define NY_BIND_ENUM_CAST(T)                                                         \
    namespace PYBIND11_NAMESPACE                                                     \
    {                                                                                \
        namespace detail                                                             \
        {                                                                            \
            template <>                                                              \
            struct type_caster<T>                                                    \
            {                                                                        \
            public:                                                                  \
                PYBIND11_TYPE_CASTER(T, const_name("T"));                            \
                bool load(handle src, bool convert)                                  \
                {                                                                    \
                    PyObject *source = src.ptr();                                    \
                    PyObject *tmp = PyNumber_Long(source);                           \
                    if (!tmp)                                                        \
                        return false;                                                \
                    value = (T)PyLong_AsLong(tmp);                                   \
                    Py_DECREF(tmp);                                                  \
                    return !PyErr_Occurred();                                        \
                }                                                                    \
                static handle cast(T src, return_value_policy policy, handle parent) \
                {                                                                    \
                    return PyLong_FromLong(src);                                     \
                }                                                                    \
            };                                                                       \
        }                                                                            \
    }

#define FIELD_TYPE(class_name, field_name) decltype(std::declval<class_name>().field_name)
#define _OPT(T, V) (V ? std::optional(T(V)) : std::nullopt)

// just for now, use ctypes to convert function pointer to size_t....
#define _NY_BIND_DEF_C_FUNC_P_FIELD(CLASS, NAME, TYPE) \
    def_property(#NAME, [](const CLASS &self) { return _OPT(std::function<std::remove_pointer_t<TYPE>>, self.NAME); }, [](CLASS &self, std::optional<size_t> func_ptr) { self.NAME = func_ptr ? (TYPE)(*func_ptr) : nullptr; })
#define NY_BIND_DEF_C_FUNC_P_FIELD(CLASS, NAME) _NY_BIND_DEF_C_FUNC_P_FIELD(CLASS, NAME, FIELD_TYPE(CLASS, NAME))

//#define NY_BIND_DEF_CHAR_P_FIELD(CLASS, NAME) \
//    def_property( \
//        #NAME, \
//        [](const CLASS& self) { if (self.NAME) return py::bytes(self.NAME); return py::none(); }, \
//        [](CLASS& self, const py::object& obj) { NY_BIND::set_char_p(&self.NAME, obj); } \
//    )
#define NY_BIND_DEF_CHAR_P_FIELD(CLS_OBJ, CLASS, NAME) NY_BIND::def_pointer<&CLASS::NAME>(CLS_OBJ, #NAME);

#define NY_BIND_DEF_CHAR_ARR_FIELD(CLASS, NAME) \
    def_property(#NAME, [](const CLASS &self) { return py::bytes(self.NAME, sizeof(self.NAME)); }, [](CLASS &self, const py::bytes &str) { NY_BIND::set_char_arr(self.NAME, str, sizeof(self.NAME)); })
