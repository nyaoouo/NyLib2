// _ny_pdb.cpp - pybind11 module bindings over dia_wrap.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "dia_wrap.hpp"

namespace py = pybind11;
using namespace ny_pdb;

PYBIND11_MODULE(_ny_pdb, m) {
    m.doc() = "_ny_pdb - thin pybind11 wrapper over Microsoft DIA SDK (msdia140.dll)";

    py::register_exception<DiaError>(m, "DiaError", PyExc_RuntimeError);

    // ---------- Symbol / Type / Member ----------
    // Declared before any .def(): they reference each other and pybind11 resolves signature types at .def() time.
    py::class_<DiaSymbol> symbol_cls(m, "Symbol");
    py::class_<DiaType> type_cls(m, "Type");
    py::class_<DiaMember> member_cls(m, "Member");

    symbol_cls
        .def_property_readonly("name", &DiaSymbol::name)
        .def_property_readonly("undecorated_name", &DiaSymbol::undecorated_name)
        .def_property_readonly("tag_id", &DiaSymbol::tag_id)
        .def_property_readonly("tag", &DiaSymbol::tag)
        .def_property_readonly("length", &DiaSymbol::length)
        .def_property_readonly("rva", &DiaSymbol::rva)
        .def_property_readonly("va", [](const DiaSymbol& s){ return s.va(true); },
                               "Virtual address; raises DiaError if session.load_address is unset.")
        .def_property_readonly("section", &DiaSymbol::section)
        .def_property_readonly("offset", &DiaSymbol::offset)
        .def_property_readonly("sym_index_id", &DiaSymbol::sym_index_id)
        .def_property_readonly("type", &DiaSymbol::type)
        .def("__repr__", [](const DiaSymbol& s){
            return "<Symbol " + s.tag() + " '" + s.name() + "' rva=0x" +
                   [&]{ char b[16]; std::snprintf(b, sizeof(b), "%x", s.rva()); return std::string(b); }() + ">";
        });

    member_cls
        .def_property_readonly("name", &DiaMember::name)
        .def_property_readonly("offset", &DiaMember::offset,
                               "Byte offset for UDT fields; -1 for statics/enums.")
        .def_property_readonly("bit_offset", &DiaMember::bit_offset,
                               "Bit offset for bitfields; -1 otherwise.")
        .def_property_readonly("bit_length", &DiaMember::bit_length,
                               "Bit width for bitfields; 0 otherwise.")
        .def_property_readonly("enum_value", &DiaMember::enum_value,
                               "Integer value for enum constants; None otherwise.")
        .def_property_readonly("type", &DiaMember::type)
        .def_property_readonly("tag_id", &DiaMember::tag_id)
        .def_property_readonly("tag", &DiaMember::tag)
        .def("__repr__", [](const DiaMember& m){
            return "<Member '" + m.name() + "' @ " +
                   std::to_string(m.offset()) + ">";
        });

    type_cls
        .def_property_readonly("name", &DiaType::name)
        .def_property_readonly("tag_id", &DiaType::tag_id)
        .def_property_readonly("tag", &DiaType::tag)
        .def_property_readonly("size", &DiaType::size)
        .def_property_readonly("count", &DiaType::count,
                               "Array element count; 0 unless this is an array type.")
        .def_property_readonly("base_kind", &DiaType::base_kind,
                               "BasicType value for a basetype; None otherwise.")
        .def_property_readonly("sym_index_id", &DiaType::sym_index_id)
        .def("members", &DiaType::members,
             "Iterate ALL children (UDT fields, enum constants, bases, methods, statics).")
        .def("fields", &DiaType::fields,
             "Instance data members only (excludes bases/methods/statics).")
        .def("base_type", &DiaType::base_type,
             "Underlying type for Typedef/Pointer/Array; None otherwise.")
        .def("__repr__", [](const DiaType& t){
            return "<Type " + t.tag() + " '" + t.name() + "' size=" +
                   std::to_string(t.size()) + ">";
        });

    // ---------- Session ----------
    py::class_<DiaSession, std::shared_ptr<DiaSession>>(m, "Session")
        .def(py::init([](const std::string& pdb_path, std::optional<ULONGLONG> load_address) {
                 auto s = DiaSession::open_pdb(pdb_path);
                 if (load_address) s->set_load_address(*load_address);
                 return s;
             }), py::arg("pdb_path"), py::arg("load_address") = std::nullopt,
             "Open a .pdb via msdia140.dll (bundled next to the pyd only; no "
             "PATH/CWD/system-search fallback). If load_address is given, "
             "session.load_address is set after open.")
        .def("close", &DiaSession::close)
        .def("__enter__", [](std::shared_ptr<DiaSession> s){ return s; })
        .def("__exit__",  [](DiaSession& s, py::object, py::object, py::object){ s.close(); })
        .def_property_readonly("pdb_signature", &DiaSession::pdb_signature,
                               "(guid_hex_no_dashes, age) tuple.")
        .def_property_readonly("pdb_path", [](const DiaSession& s){ return s.pdb_path; })
        .def_property("load_address", &DiaSession::get_load_address, &DiaSession::set_load_address,
                      "Base VA; once set, Symbol.va is valid.")
        .def("machine", &DiaSession::machine_type,
             "Image machine type (IMAGE_FILE_MACHINE_*).")
        .def("find_symbol",       &DiaSession::find_symbol,   py::arg("name"))
        .def("find_symbols",      &DiaSession::find_symbols,
             py::arg("pattern") = std::string("*"), py::arg("tag") = std::nullopt,
             "fnmatch pattern; tag filters to a SymTag (None/0 = all).")
        .def("symbol_at",         &DiaSession::symbol_at,
             py::arg("rva"), py::arg("tag") = static_cast<DWORD>(SymTagNull))
        .def("public_symbol_at",  &DiaSession::public_symbol_at, py::arg("rva"))
        .def("describe",          &DiaSession::describe,     py::arg("rva"),
             "Human label for rva: 'Name' on an exact hit, else 'Name+0xN'.")
        .def("find_type",         &DiaSession::find_type,     py::arg("name"))
        .def("find_types",        &DiaSession::find_types,    py::arg("pattern") = std::string("*"))
        .def("compilands",        &DiaSession::compilands)
        .def("raw_find",          &DiaSession::raw_find,
             py::arg("pattern"), py::arg("flags"), py::arg("tag") = 0,
             "Escape hatch: raw IDiaSymbol::findChildren(tag, pattern, flags).");
}
