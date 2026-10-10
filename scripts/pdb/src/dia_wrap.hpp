// dia_wrap.hpp - thin RAII wrappers over Microsoft DIA SDK (msdia140.dll).
//
// Design notes:
//   * COM refcounts owned by CComPtr; every IDiaXxx* released deterministically.
//   * DiaSymbol/DiaType share the same underlying IDiaSymbol* - the split is
//     only for Python API ergonomics (a Type has extra members() / base_type()).
//   * Sessions are independent - no global state in the module.
//   * msdia140.dll is loaded via NoRegCoCreate (no regsvr32 required); the
//     path is resolved relative to the compiled .pyd so a bundled dll works.
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atlbase.h>
#include <dia2.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace ny_pdb {

// Thrown by everything that talks to DIA when a call fails.
class DiaError : public std::runtime_error {
public:
    HRESULT hr;
    DiaError(HRESULT h, const std::string& what)
        : std::runtime_error(what + " (HRESULT=0x" + hex_(h) + ")"), hr(h) {}
private:
    static std::string hex_(HRESULT h) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08lx", static_cast<unsigned long>(h));
        return buf;
    }
};

// Ensure msdia140.dll is loaded from the .pyd's directory (bundled-only, no
// PATH/CWD/system-search fallback). Idempotent. Called lazily on first
// Session construction.
void ensure_msdia_loaded();

// Utility: BSTR -> std::string (UTF-8).
std::string bstr_to_utf8(BSTR b);

// Utility: std::string (UTF-8) -> BSTR (caller frees via SysFreeString via CComBSTR).
CComBSTR utf8_to_bstr(const std::string& s);

class DiaSession;
class DiaType;

// Wraps IDiaSymbol. Copies AddRef the underlying symbol; destruction Release's.
class DiaSymbol {
public:
    std::shared_ptr<DiaSession> owner;   // keeps IDiaSession alive
    CComPtr<IDiaSymbol> sym;

    DiaSymbol() = default;
    DiaSymbol(std::shared_ptr<DiaSession> o, CComPtr<IDiaSymbol> s)
        : owner(std::move(o)), sym(std::move(s)) {}

    // --- properties ---
    std::string name() const;
    std::string undecorated_name() const;
    DWORD tag_id() const;                    // raw SymTagEnum value
    std::string tag() const;                 // human-readable tag name
    ULONGLONG length() const;
    DWORD rva() const;
    ULONGLONG va(bool require_load_addr) const;  // throws if load_addr unset & required
    DWORD section() const;
    LONG offset() const;                     // relative offset (for members)
    DWORD sym_index_id() const;
    std::optional<DiaType> type() const;

    // --- extension properties ---
    bool is_function() const;                // PublicSymbol only: true iff DIA flags the public as a function
    bool is_code() const;                    // PublicSymbol only: true iff DIA flags the public as code
    std::optional<DWORD> data_kind() const;  // DataKind for a Data symbol; nullopt otherwise
    bool is_static() const;                  // Function symbols only: true iff file-static
    DWORD location_type() const;             // LocationType; LocIsNull unless S_OK
};

// A member of a UDT or an enum - carries name/offset/type + bitfield info.
class DiaMember {
public:
    std::shared_ptr<DiaSession> owner;
    CComPtr<IDiaSymbol> sym;

    DiaMember() = default;
    DiaMember(std::shared_ptr<DiaSession> o, CComPtr<IDiaSymbol> s)
        : owner(std::move(o)), sym(std::move(s)) {}

    std::string name() const;
    LONG offset() const;                     // byte offset of a field/bitfield/non-virtual base; -1 otherwise
    LONG bit_offset() const;                 // -1 if not a bitfield
    ULONGLONG bit_length() const;            // 0 if not a bitfield
    std::optional<LONGLONG> enum_value() const;  // filled only for enum members
    std::optional<DiaType> type() const;
    DWORD tag_id() const;
    std::string tag() const;
    DWORD access() const;                    // CV_access_e (1/2/3); 0 unless S_OK
};

// A DIA "type" symbol (UDT / Enum / Pointer / Array / Typedef / BaseType ...).
class DiaType {
public:
    std::shared_ptr<DiaSession> owner;
    CComPtr<IDiaSymbol> sym;

    DiaType() = default;
    DiaType(std::shared_ptr<DiaSession> o, CComPtr<IDiaSymbol> s)
        : owner(std::move(o)), sym(std::move(s)) {}

    std::string name() const;                // synthesised from base_kind/size for a basetype
    DWORD tag_id() const;
    std::string tag() const;
    ULONGLONG size() const;                  // bytes
    DWORD count() const;                     // array element count; 0 unless tag_id == SymTagArrayType
    std::optional<DWORD> base_kind() const;  // BasicType for a basetype; nullopt otherwise
    std::vector<DiaMember> members() const;  // ALL children (UDT fields, enum constants, bases, methods, statics)
    std::vector<DiaMember> fields() const;   // instance data members only (SymTagData + DataIsMember)
    std::optional<DiaType> base_type() const; // Typedef/Pointer/Array underlying
    DWORD sym_index_id() const;

    // --- extension properties ---
    std::optional<DWORD> udt_kind() const;   // UdtKind for a UDT; nullopt otherwise
    bool is_const() const;                   // true iff get_constType is S_OK and TRUE
    bool is_volatile() const;                // true iff get_volatileType is S_OK and TRUE
    bool is_unaligned() const;               // true iff get_unalignedType is S_OK and TRUE
    bool is_reference() const;               // true iff get_reference is S_OK and TRUE
    bool is_rvalue_reference() const;        // true iff get_RValueReference is S_OK and TRUE
    std::optional<DWORD> calling_convention() const;  // CV_call_e for a FunctionType; nullopt otherwise
    std::optional<DiaType> class_parent() const;      // enclosing class; nullopt unless S_OK and non-null
};

// Wraps IDiaDataSource + IDiaSession + global scope for one open PDB.
class DiaSession : public std::enable_shared_from_this<DiaSession> {
public:
    CComPtr<IDiaDataSource> source;
    CComPtr<IDiaSession>    session;
    CComPtr<IDiaSymbol>     global;

    ULONGLONG load_address = 0;
    bool load_address_set = false;

    std::string pdb_path;

    static std::shared_ptr<DiaSession> open_pdb(const std::string& pdb_path);

    void close();

    // (guid_hex_no_dashes, age)
    std::pair<std::string, DWORD> pdb_signature() const;
    DWORD machine_type() const;

    void set_load_address(ULONGLONG addr);
    ULONGLONG get_load_address() const;

    // Symbol lookup
    std::optional<DiaSymbol> find_symbol(const std::string& name) const;
    std::vector<DiaSymbol>   find_symbols(const std::string& pattern, std::optional<DWORD> tag) const;
    std::optional<DiaSymbol> symbol_at(DWORD rva, DWORD tag) const;
    std::optional<DiaSymbol> public_symbol_at(DWORD rva) const;

    // Human label for rva: 'Name' on an exact hit, else 'Name+0xN' (climbs to
    // the nearest named lexical-parent ancestor when the resolved symbol is
    // unnamed, e.g. a Block). nullopt when no symbol resolves.
    std::optional<std::string> describe(DWORD rva) const;

    // Type lookup
    std::optional<DiaType> find_type(const std::string& name) const;
    std::vector<DiaType>   find_types(const std::string& pattern) const;

    // Compilands (source modules)
    std::vector<DiaSymbol> compilands() const;

    // Escape hatch: raw findChildren with caller-supplied flags / tag.
    // Documented public helper - callers that need msdia flag combos we
    // didn't wrap can reach through here.
    std::vector<DiaSymbol> raw_find(const std::string& pattern, DWORD flags, DWORD tag) const;

private:
    DiaSession() = default;
};

// Map SymTagEnum -> lowercase name ("function", "publicsymbol", "udt", ...).
const char* sym_tag_name(DWORD tag);

} // namespace ny_pdb
