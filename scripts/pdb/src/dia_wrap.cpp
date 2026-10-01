// dia_wrap.cpp - implementation.
#include "dia_wrap.hpp"

#include <diacreate.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <mutex>

namespace ny_pdb {

// ---------- msdia140.dll loading ----------
namespace {
std::once_flag g_load_once;
HMODULE g_msdia = nullptr;
std::wstring g_msdia_path;  // absolute path of the bundled dll, set once loaded

// Locate the DLL that houses this function (i.e. our .pyd) and return its
// parent directory as an absolute wide path (no trailing separator).
std::wstring self_dir_() {
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&self_dir_), &self)) {
        return L"";
    }
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(self, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    std::wstring p(buf, n);
    size_t sep = p.find_last_of(L"\\/");
    if (sep == std::wstring::npos) return L"";
    return p.substr(0, sep);
}

std::string wide_to_utf8_(const std::wstring& w) {
    if (w.empty()) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), need,
                        nullptr, nullptr);
    return out;
}
} // namespace

void ensure_msdia_loaded() {
    std::call_once(g_load_once, []() {
        // Bundled-only load: resolve the absolute path next to the .pyd and
        // load ONLY that path - a full path passed to LoadLibrary makes Windows
        // search that path alone, so no PATH/CWD/system-search fallback remains.
        std::wstring dir = self_dir_();
        if (dir.empty()) {
            throw DiaError(E_FAIL,
                "cannot resolve the extension's own directory to locate the bundled "
                "msdia140.dll - build it with: scripts/pdb/build.py");
        }
        std::wstring full = dir + L"\\msdia140.dll";
        g_msdia = LoadLibraryExW(full.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!g_msdia) {
            DWORD err = GetLastError();
            throw DiaError(HRESULT_FROM_WIN32(err),
                "msdia140.dll not found or failed to load (expected bundled at '" +
                wide_to_utf8_(full) + "') - build it with: scripts/pdb/build.py");
        }
        g_msdia_path = full;
    });
}

// ---------- string helpers ----------
std::string bstr_to_utf8(BSTR b) {
    if (!b) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, b, -1, nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<size_t>(need - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, b, -1, out.data(), need, nullptr, nullptr);
    return out;
}

CComBSTR utf8_to_bstr(const std::string& s) {
    if (s.empty()) return CComBSTR(L"");
    int need = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (need <= 0) return CComBSTR(L"");
    std::wstring wide(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), wide.data(), need);
    return CComBSTR(static_cast<int>(wide.size()), wide.data());
}

// ---------- SymTag name map ----------
const char* sym_tag_name(DWORD tag) {
    switch (tag) {
        case SymTagNull:              return "null";
        case SymTagExe:               return "exe";
        case SymTagCompiland:         return "compiland";
        case SymTagCompilandDetails:  return "compilanddetails";
        case SymTagCompilandEnv:      return "compilandenv";
        case SymTagFunction:          return "function";
        case SymTagBlock:             return "block";
        case SymTagData:              return "data";
        case SymTagAnnotation:        return "annotation";
        case SymTagLabel:             return "label";
        case SymTagPublicSymbol:      return "publicsymbol";
        case SymTagUDT:               return "udt";
        case SymTagEnum:              return "enum";
        case SymTagFunctionType:      return "functiontype";
        case SymTagPointerType:       return "pointertype";
        case SymTagArrayType:         return "arraytype";
        case SymTagBaseType:          return "basetype";
        case SymTagTypedef:           return "typedef";
        case SymTagBaseClass:         return "baseclass";
        case SymTagFriend:            return "friend";
        case SymTagFunctionArgType:   return "functionargtype";
        case SymTagFuncDebugStart:    return "funcdebugstart";
        case SymTagFuncDebugEnd:      return "funcdebugend";
        case SymTagUsingNamespace:    return "usingnamespace";
        case SymTagVTableShape:       return "vtableshape";
        case SymTagVTable:            return "vtable";
        case SymTagCustom:            return "custom";
        case SymTagThunk:             return "thunk";
        case SymTagCustomType:        return "customtype";
        case SymTagManagedType:       return "managedtype";
        case SymTagDimension:         return "dimension";
        case SymTagCallSite:          return "callsite";
        case SymTagInlineSite:        return "inlinesite";
        case SymTagBaseInterface:     return "baseinterface";
        case SymTagVectorType:        return "vectortype";
        case SymTagMatrixType:        return "matrixtype";
        case SymTagHLSLType:          return "hlsltype";
        case SymTagCaller:            return "caller";
        case SymTagCallee:            return "callee";
        case SymTagExport:            return "export";
        case SymTagHeapAllocationSite:return "heapallocationsite";
        case SymTagCoffGroup:         return "coffgroup";
        case SymTagInlinee:           return "inlinee";
        case SymTagTaggedUnionCase:   return "taggedunioncase";
        default:                      return "unknown";
    }
}

// ---------- DiaSymbol / DiaType / DiaMember helpers ----------
namespace {

DWORD get_tag_(IDiaSymbol* s) {
    DWORD t = SymTagNull;
    if (s) s->get_symTag(&t);
    return t;
}

std::string get_name_(IDiaSymbol* s) {
    if (!s) return {};
    CComBSTR b;
    if (SUCCEEDED(s->get_name(&b)) && b) return bstr_to_utf8(b);
    return {};
}

std::string get_undecorated_(IDiaSymbol* s) {
    if (!s) return {};
    CComBSTR b;
    if (SUCCEEDED(s->get_undecoratedName(&b)) && b) return bstr_to_utf8(b);
    return {};
}

ULONGLONG get_length_(IDiaSymbol* s) {
    ULONGLONG v = 0;
    if (s) s->get_length(&v);
    return v;
}

DWORD get_rva_(IDiaSymbol* s) {
    DWORD v = 0;
    if (s) s->get_relativeVirtualAddress(&v);
    return v;
}

DWORD get_section_(IDiaSymbol* s) {
    DWORD v = 0;
    if (s) s->get_addressSection(&v);
    return v;
}

LONG get_offset_(IDiaSymbol* s) {
    LONG v = 0;
    if (s) s->get_offset(&v);
    return v;
}

DWORD get_locationtype_(IDiaSymbol* s) {
    DWORD v = LocIsNull;
    if (s) s->get_locationType(&v);
    return v;
}

DWORD get_datakind_(IDiaSymbol* s) {
    DWORD v = DataIsUnknown;
    if (s) s->get_dataKind(&v);
    return v;
}

// Synthesise a Type.name for a basetype from (BasicType, size) - DIA's own
// get_name() is empty for these. Unmapped combos still get a deterministic
// non-empty name so the fallback can never regress to ''.
std::string basetype_name_(DWORD base_kind, ULONGLONG size) {
    struct Entry { DWORD kind; ULONGLONG size; const char* name; };
    static const Entry table[] = {
        {btVoid,    0,  "void"},
        {btChar,    1,  "char"},
        {btWChar,   2,  "wchar_t"},
        {btInt,     1,  "signed char"},
        {btInt,     2,  "short"},
        {btInt,     4,  "int"},
        {btInt,     8,  "__int64"},
        {btUInt,    1,  "unsigned char"},
        {btUInt,    2,  "unsigned short"},
        {btUInt,    4,  "unsigned int"},
        {btUInt,    8,  "unsigned __int64"},
        {btFloat,   4,  "float"},
        {btFloat,   8,  "double"},
        {btFloat,   10, "long double"},
        {btBool,    1,  "bool"},
        {btLong,    4,  "long"},
        {btULong,   4,  "unsigned long"},
        {btHresult, 4,  "HRESULT"},
        {btChar16,  2,  "char16_t"},
        {btChar32,  4,  "char32_t"},
        {btChar8,   1,  "char8_t"},
    };
    for (const auto& e : table) {
        if (e.kind == base_kind && e.size == size) return e.name;
    }
    return "<bt" + std::to_string(base_kind) + ":" + std::to_string(size) + ">";
}

} // namespace

// ------ DiaSymbol ------
std::string DiaSymbol::name() const              { return get_name_(sym); }
std::string DiaSymbol::undecorated_name() const  { return get_undecorated_(sym); }
DWORD       DiaSymbol::tag_id() const            { return get_tag_(sym); }
std::string DiaSymbol::tag() const               { return sym_tag_name(tag_id()); }
ULONGLONG   DiaSymbol::length() const            { return get_length_(sym); }
DWORD       DiaSymbol::rva() const               { return get_rva_(sym); }
DWORD       DiaSymbol::section() const           { return get_section_(sym); }
LONG        DiaSymbol::offset() const            { return get_offset_(sym); }

DWORD DiaSymbol::sym_index_id() const {
    DWORD v = 0;
    if (sym) sym->get_symIndexId(&v);
    return v;
}

std::optional<DiaType> DiaSymbol::type() const {
    CComPtr<IDiaSymbol> t;
    if (!sym || sym->get_type(&t) != S_OK || !t) return std::nullopt;
    return DiaType{owner, std::move(t)};
}

ULONGLONG DiaSymbol::va(bool require_load_addr) const {
    ULONGLONG va = 0;
    if (sym) sym->get_virtualAddress(&va);
    // If the caller wants a valid VA and no load_address was set on the
    // session, DIA returns 0 (or whatever get_loadAddress returned). Signal
    // that explicitly so Python can raise.
    if (require_load_addr && owner && !owner->load_address_set) {
        throw DiaError(E_FAIL, "session.load_address is unset - VA cannot be computed");
    }
    return va;
}

// ------ DiaMember ------
std::string DiaMember::name() const { return get_name_(sym); }
DWORD DiaMember::tag_id() const { return get_tag_(sym); }
std::string DiaMember::tag() const { return sym_tag_name(tag_id()); }

LONG DiaMember::offset() const {
    // For UDT members with LocIsThisRel this is the byte offset from the
    // enclosing this pointer. LocIsBitField members share that same
    // storage-unit byte offset. Static members / enums use other location
    // types - report -1 as "no meaningful byte offset".
    DWORD loc = get_locationtype_(sym);
    if (loc == LocIsThisRel || loc == LocIsBitField) return get_offset_(sym);
    return -1;
}

LONG DiaMember::bit_offset() const {
    DWORD loc = get_locationtype_(sym);
    if (loc != LocIsBitField) return -1;
    DWORD bp = 0;
    if (SUCCEEDED(sym->get_bitPosition(&bp))) return static_cast<LONG>(bp);
    return -1;
}

ULONGLONG DiaMember::bit_length() const {
    DWORD loc = get_locationtype_(sym);
    if (loc != LocIsBitField) return 0;
    return get_length_(sym);
}

std::optional<LONGLONG> DiaMember::enum_value() const {
    // Enum constants come back as SymTagData with a DataIsConstant kind
    // and a VARIANT value. We only surface integral values here.
    VARIANT v;
    VariantInit(&v);
    if (FAILED(sym->get_value(&v))) return std::nullopt;
    std::optional<LONGLONG> out;
    switch (v.vt) {
        case VT_I1:  out = v.cVal; break;
        case VT_UI1: out = v.bVal; break;
        case VT_I2:  out = v.iVal; break;
        case VT_UI2: out = v.uiVal; break;
        case VT_I4:  out = v.lVal; break;
        case VT_UI4: out = static_cast<LONGLONG>(v.ulVal); break;
        case VT_INT: out = v.intVal; break;
        case VT_UINT: out = static_cast<LONGLONG>(v.uintVal); break;
        case VT_I8:  out = v.llVal; break;
        case VT_UI8: out = static_cast<LONGLONG>(v.ullVal); break;
        default: break;
    }
    VariantClear(&v);
    return out;
}

std::optional<DiaType> DiaMember::type() const {
    CComPtr<IDiaSymbol> t;
    if (FAILED(sym->get_type(&t)) || !t) return std::nullopt;
    return DiaType{owner, std::move(t)};
}

// ------ DiaType ------
std::string DiaType::name() const {
    // DIA's own get_name() is always empty for a basetype - synthesise a
    // deterministic non-empty name from (base_kind, size) instead.
    if (tag_id() == SymTagBaseType) {
        DWORD bt = btNoType;
        if (sym) sym->get_baseType(&bt);
        return basetype_name_(bt, size());
    }
    return get_name_(sym);
}
DWORD DiaType::tag_id() const { return get_tag_(sym); }
std::string DiaType::tag() const { return sym_tag_name(tag_id()); }
ULONGLONG DiaType::size() const { return get_length_(sym); }
DWORD DiaType::sym_index_id() const {
    DWORD v = 0;
    if (sym) sym->get_symIndexId(&v);
    return v;
}

DWORD DiaType::count() const {
    // get_count also reports a function type's parameter count - guard it to
    // arrays only so callers can't mistake one for the other.
    if (tag_id() != SymTagArrayType) return 0;
    DWORD c = 0;
    if (sym) sym->get_count(&c);
    return c;
}

std::optional<DWORD> DiaType::base_kind() const {
    if (tag_id() != SymTagBaseType) return std::nullopt;
    DWORD bt = 0;
    if (sym && SUCCEEDED(sym->get_baseType(&bt))) return bt;
    return std::nullopt;
}

std::vector<DiaMember> DiaType::members() const {
    std::vector<DiaMember> out;
    CComPtr<IDiaEnumSymbols> e;
    if (FAILED(sym->findChildren(SymTagNull, nullptr, nsNone, &e)) || !e) return out;
    CComPtr<IDiaSymbol> child;
    ULONG got = 0;
    while (SUCCEEDED(e->Next(1, &child, &got)) && got == 1) {
        out.emplace_back(owner, std::move(child));
        child.Release();
    }
    return out;
}

std::vector<DiaMember> DiaType::fields() const {
    // Instance data members only: SymTagData children with DataIsMember -
    // excludes base classes, methods, nested types, and static members.
    std::vector<DiaMember> out;
    CComPtr<IDiaEnumSymbols> e;
    if (FAILED(sym->findChildren(SymTagData, nullptr, nsNone, &e)) || !e) return out;
    CComPtr<IDiaSymbol> child;
    ULONG got = 0;
    while (SUCCEEDED(e->Next(1, &child, &got)) && got == 1) {
        if (get_datakind_(child) == DataIsMember) out.emplace_back(owner, child);
        child.Release();
    }
    return out;
}

std::optional<DiaType> DiaType::base_type() const {
    CComPtr<IDiaSymbol> t;
    if (FAILED(sym->get_type(&t)) || !t) return std::nullopt;
    return DiaType{owner, std::move(t)};
}

// ------ DiaSession ------
std::shared_ptr<DiaSession> DiaSession::open_pdb(const std::string& pdb_path) {
    ensure_msdia_loaded();

    CComPtr<IDiaDataSource> src;
    // NoRegCoCreate: create IDiaDataSource without requiring regsvr32. Pass the
    // bundled dll's absolute path - never the bare name, which would let
    // Windows fall back to PATH/system search.
    HRESULT hr = NoRegCoCreate(g_msdia_path.c_str(), CLSID_DiaSource, IID_IDiaDataSource,
                               reinterpret_cast<void**>(&src));
    if (FAILED(hr) || !src) {
        throw DiaError(hr, "NoRegCoCreate(msdia140.dll) failed");
    }

    // Convert utf8 path -> wide.
    int need = MultiByteToWideChar(CP_UTF8, 0, pdb_path.data(), static_cast<int>(pdb_path.size()),
                                   nullptr, 0);
    std::wstring w(need, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, pdb_path.data(), static_cast<int>(pdb_path.size()),
                        w.data(), need);

    hr = src->loadDataFromPdb(w.c_str());
    if (FAILED(hr)) throw DiaError(hr, "loadDataFromPdb('" + pdb_path + "')");

    CComPtr<IDiaSession> sess;
    hr = src->openSession(&sess);
    if (FAILED(hr) || !sess) throw DiaError(hr, "openSession");

    CComPtr<IDiaSymbol> global;
    hr = sess->get_globalScope(&global);
    if (FAILED(hr) || !global) throw DiaError(hr, "get_globalScope");

    auto out = std::shared_ptr<DiaSession>(new DiaSession());
    out->source = std::move(src);
    out->session = std::move(sess);
    out->global = std::move(global);
    out->pdb_path = pdb_path;
    return out;
}

void DiaSession::close() {
    global.Release();
    session.Release();
    source.Release();
    load_address = 0;
    load_address_set = false;
}

std::pair<std::string, DWORD> DiaSession::pdb_signature() const {
    // guid: from IDiaSymbol (SymTagExe) get_guid + get_age
    GUID g{};
    DWORD age = 0;
    if (global) {
        global->get_guid(&g);
        global->get_age(&age);
    }
    char buf[33];
    std::snprintf(buf, sizeof(buf),
        "%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        static_cast<unsigned long>(g.Data1), g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return {std::string(buf), age};
}

DWORD DiaSession::machine_type() const {
    DWORD m = 0;
    if (global) global->get_machineType(&m);
    return m;
}

void DiaSession::set_load_address(ULONGLONG addr) {
    if (session) {
        HRESULT hr = session->put_loadAddress(addr);
        if (FAILED(hr)) throw DiaError(hr, "put_loadAddress");
    }
    load_address = addr;
    load_address_set = true;
}

ULONGLONG DiaSession::get_load_address() const { return load_address; }

std::optional<DiaSymbol> DiaSession::find_symbol(const std::string& name) const {
    if (!global) return std::nullopt;
    auto wname = utf8_to_bstr(name);
    CComPtr<IDiaEnumSymbols> e;
    if (FAILED(global->findChildren(SymTagNull, wname, nsCaseSensitive, &e)) || !e) {
        return std::nullopt;
    }
    CComPtr<IDiaSymbol> s;
    ULONG got = 0;
    if (SUCCEEDED(e->Next(1, &s, &got)) && got == 1) {
        return DiaSymbol{const_cast<DiaSession*>(this)->shared_from_this(), std::move(s)};
    }
    return std::nullopt;
}

std::vector<DiaSymbol> DiaSession::find_symbols(const std::string& pattern, std::optional<DWORD> tag) const {
    std::vector<DiaSymbol> out;
    if (!global) return out;
    if (pattern.empty()) return out;  // guard before calling DIA
    // Empirically: msdia140 only honours patterns when the flag mask is
    // ``nsCaseInRegularExpression = nsfCaseInsensitive | nsfRegularExpression``
    // (= 0x0A). Despite the "RegularExpression" name, the pattern grammar in
    // that mode is fnmatch (``*`` any, ``?`` one). Other combos silently
    // return the empty enumerator.
    auto wpat = utf8_to_bstr(pattern);
    auto tag_value = static_cast<enum SymTagEnum>(tag.value_or(SymTagNull));
    CComPtr<IDiaEnumSymbols> e;
    if (FAILED(global->findChildren(tag_value, wpat, nsCaseInRegularExpression, &e)) || !e) {
        return out;
    }
    CComPtr<IDiaSymbol> s;
    ULONG got = 0;
    while (SUCCEEDED(e->Next(1, &s, &got)) && got == 1) {
        out.emplace_back(const_cast<DiaSession*>(this)->shared_from_this(), std::move(s));
        s.Release();
    }
    return out;
}

std::optional<DiaSymbol> DiaSession::symbol_at(DWORD rva, DWORD tag) const {
    if (!session) return std::nullopt;
    CComPtr<IDiaSymbol> s;
    if (FAILED(session->findSymbolByRVA(rva, static_cast<enum SymTagEnum>(tag), &s)) || !s) {
        return std::nullopt;
    }
    return DiaSymbol{const_cast<DiaSession*>(this)->shared_from_this(), std::move(s)};
}

std::optional<DiaSymbol> DiaSession::public_symbol_at(DWORD rva) const {
    if (!session) return std::nullopt;
    CComPtr<IDiaSymbol> s;
    if (FAILED(session->findSymbolByRVA(rva, SymTagPublicSymbol, &s)) || !s) return std::nullopt;
    return DiaSymbol{const_cast<DiaSession*>(this)->shared_from_this(), std::move(s)};
}

namespace {
constexpr DWORD kUndnameNameOnly = 0x1000;  // UNDNAME_NAME_ONLY (dbghelp.h)

// Climb sym's lexicalParent chain to the nearest ancestor that has both a
// name and a resolvable RVA (its enclosing Function, typically). "Carries an
// RVA" means get_relativeVirtualAddress returns exactly S_OK - S_FALSE
// (returned by Compiland/Exe with rva 0) does not qualify, and the climb
// stops at a Compiland or Exe tag (e.g. an incremental-link ILT thunk whose
// parent is the "* Linker *" compiland must not resolve to that compiland).
CComPtr<IDiaSymbol> climb_to_named_ancestor_(IDiaSymbol* sym) {
    CComPtr<IDiaSymbol> cur;
    if (!sym || FAILED(sym->get_lexicalParent(&cur)) || !cur) return nullptr;
    while (cur) {
        DWORD cur_tag = get_tag_(cur);
        if (cur_tag == SymTagCompiland || cur_tag == SymTagExe) return nullptr;
        DWORD rva = 0;
        if (!get_name_(cur).empty() && cur->get_relativeVirtualAddress(&rva) == S_OK) {
            return cur;
        }
        CComPtr<IDiaSymbol> parent;
        if (FAILED(cur->get_lexicalParent(&parent)) || !parent) return nullptr;
        cur = parent;
    }
    return nullptr;
}
} // namespace

std::optional<std::string> DiaSession::describe(DWORD rva) const {
    if (!session) return std::nullopt;
    CComPtr<IDiaSymbol> sym;
    long disp = 0;
    if (FAILED(session->findSymbolByRVAEx(rva, SymTagNull, &sym, &disp)) || !sym) {
        return std::nullopt;
    }

    CComPtr<IDiaSymbol> named = sym;
    if (get_name_(sym).empty()) {
        named = climb_to_named_ancestor_(sym);
        if (!named) return std::nullopt;
    }

    // Same S_OK rule as the climb (S_FALSE means "no RVA" - reject it).
    DWORD base_rva = 0;
    if (named->get_relativeVirtualAddress(&base_rva) != S_OK) {
        return std::nullopt;
    }

    // Name-only undecoration is chosen by whether the name is decorated: a
    // private Function/Data name from DIA is already name-only, but an
    // MSVC-decorated public name ('?'-prefixed) needs get_undecoratedNameEx.
    // A "contains '('" heuristic is wrong here - it rejects legitimate
    // name-only results like 'Functor::operator()' - so key on the '?'
    // prefix instead.
    std::string label = get_name_(named);
    if (!label.empty() && label[0] == '?') {
        CComBSTR undecorated;
        if (named->get_undecoratedNameEx(kUndnameNameOnly, &undecorated) == S_OK &&
            undecorated.Length() > 0) {
            label = bstr_to_utf8(undecorated);
        }
    }
    if (label.empty()) return std::nullopt;

    // Signed delta: a negative displacement (shouldn't normally happen, but
    // is possible for a pathological ancestor) means no valid label either.
    long long delta_ll = static_cast<long long>(rva) - static_cast<long long>(base_rva);
    if (delta_ll < 0) return std::nullopt;
    DWORD delta = static_cast<DWORD>(delta_ll);
    if (delta == 0) return label;
    char buf[24];
    std::snprintf(buf, sizeof(buf), "+0x%x", delta);
    return label + buf;
}

std::optional<DiaType> DiaSession::find_type(const std::string& name) const {
    if (!global) return std::nullopt;
    auto wname = utf8_to_bstr(name);
    // Types live as UDT/Enum/Typedef children of the global scope.
    // Try each tag; return the first hit. Users can pass either mangled
    // or plain names.
    const enum SymTagEnum tags[] = { SymTagUDT, SymTagEnum, SymTagTypedef,
                                     SymTagBaseType, SymTagPointerType,
                                     SymTagArrayType, SymTagFunctionType };
    for (auto t : tags) {
        CComPtr<IDiaEnumSymbols> e;
        if (FAILED(global->findChildren(t, wname, nsCaseSensitive, &e)) || !e) continue;
        CComPtr<IDiaSymbol> s;
        ULONG got = 0;
        if (SUCCEEDED(e->Next(1, &s, &got)) && got == 1) {
            return DiaType{const_cast<DiaSession*>(this)->shared_from_this(), std::move(s)};
        }
    }
    return std::nullopt;
}

std::vector<DiaType> DiaSession::find_types(const std::string& pattern) const {
    std::vector<DiaType> out;
    if (!global) return out;
    // See find_symbols() for the flag rationale.
    auto wpat = utf8_to_bstr(pattern);
    const enum SymTagEnum tags[] = { SymTagUDT, SymTagEnum, SymTagTypedef,
                                     SymTagBaseType, SymTagPointerType,
                                     SymTagArrayType, SymTagFunctionType };
    for (auto t : tags) {
        CComPtr<IDiaEnumSymbols> e;
        if (FAILED(global->findChildren(t, wpat, nsCaseInRegularExpression, &e)) || !e) continue;
        CComPtr<IDiaSymbol> s;
        ULONG got = 0;
        while (SUCCEEDED(e->Next(1, &s, &got)) && got == 1) {
            out.emplace_back(const_cast<DiaSession*>(this)->shared_from_this(), std::move(s));
            s.Release();
        }
    }
    return out;
}

std::vector<DiaSymbol> DiaSession::raw_find(const std::string& pattern, DWORD flags, DWORD tag) const {
    std::vector<DiaSymbol> out;
    if (!global) return out;
    auto wpat = utf8_to_bstr(pattern);
    CComPtr<IDiaEnumSymbols> e;
    HRESULT hr = global->findChildren(static_cast<enum SymTagEnum>(tag), wpat, flags, &e);
    if (FAILED(hr) || !e) return out;
    CComPtr<IDiaSymbol> s;
    ULONG got = 0;
    while (SUCCEEDED(e->Next(1, &s, &got)) && got == 1) {
        out.emplace_back(const_cast<DiaSession*>(this)->shared_from_this(), std::move(s));
        s.Release();
    }
    return out;
}

std::vector<DiaSymbol> DiaSession::compilands() const {
    std::vector<DiaSymbol> out;
    if (!global) return out;
    CComPtr<IDiaEnumSymbols> e;
    if (FAILED(global->findChildren(SymTagCompiland, nullptr, nsNone, &e)) || !e) return out;
    CComPtr<IDiaSymbol> s;
    ULONG got = 0;
    while (SUCCEEDED(e->Next(1, &s, &got)) && got == 1) {
        out.emplace_back(const_cast<DiaSession*>(this)->shared_from_this(), std::move(s));
        s.Release();
    }
    return out;
}

} // namespace ny_pdb
