#include "./Win32Font.h"

#include <dwrite.h>
#include <dwrite_1.h>
#include <dwrite_2.h>
#include <wrl/client.h>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "dwrite.lib")

using Microsoft::WRL::ComPtr;

START_WIN32FONT_NAMESPACE
{
namespace {

// ============================================================
// SECTION 1 — DirectWrite factory + utf16/utf8 helpers
// ============================================================

struct DWriteFactoryHolder {
    ComPtr<IDWriteFactory>  factory;
    ComPtr<IDWriteFactory2> factory2;  // GetSystemFontFallback lives here
};

DWriteFactoryHolder& GetFactory()
{
    static DWriteFactoryHolder holder;
    static std::once_flag once;
    std::call_once(once, [&]() {
        HRESULT hr = DWriteCreateFactory(
            DWRITE_FACTORY_TYPE_SHARED,
            __uuidof(IDWriteFactory),
            reinterpret_cast<IUnknown**>(holder.factory.GetAddressOf()));
        if (FAILED(hr))
            _throwV_("DWriteCreateFactory failed hr=0x{:08x}", static_cast<unsigned>(hr));
        // factory2 (Win8+) is optional; absence => MapCharacters API unavailable.
        (void)holder.factory.As(&holder.factory2);
    });
    return holder;
}

std::string WstrToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), sz, nullptr, nullptr);
    return s;
}

std::wstring Utf8ToWstr(const std::string& s)
{
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                  nullptr, 0);
    std::wstring w(static_cast<size_t>(sz), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        w.data(), sz);
    return w;
}

// ============================================================
// SECTION 2 — Font face introspection
//   ResolveLocalFilePath, ExtractGlyphRanges,
//   GetLocalizedFamilyName, BuildMatchFromFont
// ============================================================

bool ResolveLocalFilePath(IDWriteFontFace* face,
                          std::wstring& out_path,
                          int& out_face_index)
{
    if (!face) return false;
    UINT32 file_count = 0;
    if (FAILED(face->GetFiles(&file_count, nullptr)) || file_count != 1)
        return false;  // .ttf/.ttc are single-file

    ComPtr<IDWriteFontFile> file;
    if (FAILED(face->GetFiles(&file_count, file.GetAddressOf())) || !file)
        return false;

    const void* ref_key = nullptr;
    UINT32 ref_key_size = 0;
    if (FAILED(file->GetReferenceKey(&ref_key, &ref_key_size)))
        return false;

    ComPtr<IDWriteFontFileLoader> loader;
    if (FAILED(file->GetLoader(loader.GetAddressOf())) || !loader)
        return false;

    ComPtr<IDWriteLocalFontFileLoader> local_loader;
    if (FAILED(loader.As(&local_loader)) || !local_loader)
        return false;  // remote loader (rare) — skip

    UINT32 path_len = 0;
    if (FAILED(local_loader->GetFilePathLengthFromKey(ref_key, ref_key_size, &path_len)))
        return false;

    // GetFilePathFromKey writes path_len chars + NUL, so we need path_len+1 of headroom.
    std::wstring path(static_cast<size_t>(path_len) + 1, L'\0');
    if (FAILED(local_loader->GetFilePathFromKey(ref_key, ref_key_size,
                                                 path.data(), path_len + 1)))
        return false;
    path.resize(path_len);

    out_path = std::move(path);
    out_face_index = static_cast<int>(face->GetIndex());
    return true;
}

// Codepoints > 0xFFFF are dropped (default ImGui ImWchar is 16-bit).
//
// max_pairs bounds the begin/end pair count. CJK fonts (Yu Gothic UI,
// Malgun Gothic, Microsoft YaHei) commonly expose 4000+ fragmented pairs
// in the BMP; capping too low silently truncates the tail and renders
// every Kanji/Hanzi/Hangul as tofu. 8192 is plenty for any realistic
// font; atlas size is bounded by the codepoint *count* (one range can
// encode 20k+ codepoints densely), not the pair count.
//
// ImGui treats codepoint 0 as the array-terminating sentinel — a pair
// beginning with 0 (Malgun Gothic exposes (0,0) at the head) silently
// truncates everything that follows. We skip [0,0] and clamp leading 0s.
std::vector<ImWchar> ExtractGlyphRanges(IDWriteFontFace* face,
                                        size_t max_pairs = 8192)
{
    std::vector<ImWchar> out;
    if (!face) return out;

    ComPtr<IDWriteFontFace1> face1;
    if (FAILED(face->QueryInterface(IID_PPV_ARGS(face1.GetAddressOf())))) {
        // very old DWrite — emit Basic Latin as a tiny safety net
        out.push_back(0x0020); out.push_back(0x007E);
        out.push_back(0);
        return out;
    }

    UINT32 range_count = 0;
    face1->GetUnicodeRanges(0, nullptr, &range_count);
    if (range_count == 0) {
        out.push_back(0);
        return out;
    }

    std::vector<DWRITE_UNICODE_RANGE> ranges(range_count);
    if (FAILED(face1->GetUnicodeRanges(range_count, ranges.data(), &range_count))) {
        out.push_back(0);
        return out;
    }

    size_t emitted = 0;
    for (const auto& r : ranges) {
        if (emitted >= max_pairs) break;
        UINT32 first = r.first;
        UINT32 last  = r.last;
        if (first > 0xFFFF) continue;
        if (last  > 0xFFFF) last = 0xFFFF;
        if (last == 0) continue;
        if (first == 0) first = 1;  // 0 collides with ImGui sentinel
        out.push_back(static_cast<ImWchar>(first));
        out.push_back(static_cast<ImWchar>(last));
        ++emitted;
    }
    out.push_back(0);  // ImGui sentinel
    return out;
}

// IDWriteFontFamily -> localized family name (caller locale -> en-us -> idx 0).
std::wstring GetLocalizedFamilyName(IDWriteFontFamily* family, const std::wstring& locale)
{
    if (!family) return {};
    ComPtr<IDWriteLocalizedStrings> names;
    if (FAILED(family->GetFamilyNames(names.GetAddressOf())) || !names) return {};

    UINT32 idx = 0;
    BOOL exists = FALSE;
    if (!locale.empty())
        names->FindLocaleName(locale.c_str(), &idx, &exists);
    if (!exists)
        names->FindLocaleName(L"en-us", &idx, &exists);
    if (!exists) idx = 0;

    UINT32 name_len = 0;
    if (FAILED(names->GetStringLength(idx, &name_len))) return {};
    std::wstring name(static_cast<size_t>(name_len) + 1, L'\0');
    if (FAILED(names->GetString(idx, name.data(), name_len + 1))) return {};
    name.resize(name_len);
    return name;
}

// IDWriteFont -> Win32FontMatch (file + ranges + localized family name).
// On false return, `out` may have partial state — callers must discard it.
bool BuildMatchFromFont(IDWriteFont* font,
                        const std::wstring& locale,
                        Win32FontMatch& out)
{
    if (!font) return false;

    ComPtr<IDWriteFontFace> face;
    if (FAILED(font->CreateFontFace(face.GetAddressOf())) || !face) return false;

    if (!ResolveLocalFilePath(face.Get(), out.file_path, out.face_index))
        return false;

    out.ranges = ExtractGlyphRanges(face.Get());

    ComPtr<IDWriteFontFamily> family;
    if (SUCCEEDED(font->GetFontFamily(family.GetAddressOf())) && family)
        out.family_name = GetLocalizedFamilyName(family.Get(), locale);

    out.locale = locale;
    out.suggested_size = 0.0f;
    return true;
}

// ============================================================
// SECTION 3 — DirectWrite text → font lookup
//   TextAnalysisSourceImpl, MapSampleWithHints
// ============================================================

class TextAnalysisSourceImpl : public IDWriteTextAnalysisSource
{
public:
    TextAnalysisSourceImpl(std::wstring text,
                           std::wstring locale,
                           ComPtr<IDWriteNumberSubstitution> numsub)
        : text_(std::move(text)),
          locale_(std::move(locale)),
          numsub_(std::move(numsub)) {}

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDWriteTextAnalysisSource)) {
            *ppv = static_cast<IDWriteTextAnalysisSource*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override  { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = --refs_;
        if (r == 0) delete this;
        return r;
    }

    // IDWriteTextAnalysisSource
    HRESULT STDMETHODCALLTYPE GetTextAtPosition(
        UINT32 pos, const WCHAR** out_text, UINT32* out_len) override
    {
        if (pos >= text_.size()) { *out_text = nullptr; *out_len = 0; return S_OK; }
        *out_text = text_.c_str() + pos;
        *out_len  = static_cast<UINT32>(text_.size() - pos);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetTextBeforePosition(
        UINT32 pos, const WCHAR** out_text, UINT32* out_len) override
    {
        if (pos == 0 || pos > text_.size()) { *out_text = nullptr; *out_len = 0; return S_OK; }
        *out_text = text_.c_str();
        *out_len  = pos;
        return S_OK;
    }
    DWRITE_READING_DIRECTION STDMETHODCALLTYPE GetParagraphReadingDirection() override
    {
        return DWRITE_READING_DIRECTION_LEFT_TO_RIGHT;
    }
    HRESULT STDMETHODCALLTYPE GetLocaleName(
        UINT32 pos, UINT32* out_len, const WCHAR** out_locale) override
    {
        *out_len    = static_cast<UINT32>(text_.size() - pos);
        *out_locale = locale_.empty() ? nullptr : locale_.c_str();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetNumberSubstitution(
        UINT32 pos, UINT32* out_len, IDWriteNumberSubstitution** out_ns) override
    {
        *out_len = static_cast<UINT32>(text_.size() - pos);
        *out_ns  = numsub_.Get();
        if (*out_ns) (*out_ns)->AddRef();
        return S_OK;
    }

private:
    std::wstring text_;
    std::wstring locale_;
    ComPtr<IDWriteNumberSubstitution> numsub_;
    ULONG refs_ = 1;
};

// Run IDWriteFontFallback::MapCharacters with optional hints. Returns true and
// fills out_font when DirectWrite picks a font that can render `sample`.
// - `locale` (BCP-47 or empty) biases the script selection. This is the lever
//   that distinguishes SC vs TC vs JP CJK font picks.
// - `base_family` (may be nullptr) is preferred when it can render the sample.
//   Used by GetSystemUiFont to honour LOGFONT.lfFaceName.
bool MapSampleWithHints(const std::wstring& sample,
                        const std::wstring& locale,
                        const wchar_t* base_family,
                        DWRITE_FONT_WEIGHT weight,
                        DWRITE_FONT_STYLE  style,
                        DWRITE_FONT_STRETCH stretch,
                        ComPtr<IDWriteFont>& out_font)
{
    out_font.Reset();
    if (sample.empty()) return false;

    auto& holder = GetFactory();
    if (!holder.factory2) return false;  // requires Win8+

    ComPtr<IDWriteFontFallback> fallback;
    if (FAILED(holder.factory2->GetSystemFontFallback(fallback.GetAddressOf())) || !fallback)
        return false;

    ComPtr<IDWriteFontCollection> sys_coll;
    if (FAILED(holder.factory->GetSystemFontCollection(sys_coll.GetAddressOf(), FALSE)) || !sys_coll)
        return false;

    ComPtr<IDWriteNumberSubstitution> numsub;
    holder.factory2->CreateNumberSubstitution(
        DWRITE_NUMBER_SUBSTITUTION_METHOD_NONE,
        locale.empty() ? nullptr : locale.c_str(),
        TRUE,
        numsub.GetAddressOf());

    ComPtr<TextAnalysisSourceImpl> source;
    source.Attach(new TextAnalysisSourceImpl(sample, locale, numsub));

    UINT32 mapped_len = 0;
    FLOAT  scale = 0.0f;
    HRESULT hr = fallback->MapCharacters(
        source.Get(),
        0,
        static_cast<UINT32>(sample.size()),
        sys_coll.Get(),
        base_family,
        weight,
        style,
        stretch,
        &mapped_len,
        out_font.GetAddressOf(),
        &scale);

    return SUCCEEDED(hr) && out_font && mapped_len > 0;
}

// ============================================================
// SECTION 4 — Script profile table
//
// One source of truth for both:
//   (a) MatchForLocale's fallback chain — `sample` + `locale_prefix` together
//       force DirectWrite to pick the user-region-appropriate font for each
//       script (e.g. SC sample with "zh-Hans" hint → Microsoft YaHei).
//   (b) ListFontsForLocale's coverage probes — `probes` are the codepoints
//       used with HasCharacter() to verify a font supports that script.
//
// Entries MUST be ordered specific-prefix-first so prefix matching picks the
// right entry (e.g. zh-TW matches `zh-Hant` profile, not `zh`).
// ============================================================

struct ScriptProfile {
    const wchar_t* locale_prefix;       // BCP-47 prefix (case-insensitive)
    const wchar_t* sample;              // text fed to MapCharacters
    std::vector<uint32_t> probes;       // codepoints for HasCharacter probing
};

// Probe sets — defined once and referenced by ScriptProfile entries below.
const std::vector<uint32_t>& TcProbes() {
    static const std::vector<uint32_t> v = {
        // 4 TC-distinguishing chars (繁體漢灣) + 4 shared CJK
        0x7E41, 0x9AD4, 0x6F22, 0x7063,  // 繁 體 漢 灣
        0x4E2D, 0x6587, 0x5B57, 0x53F0,  // 中 文 字 台
    };
    return v;
}
const std::vector<uint32_t>& ScProbes() {
    static const std::vector<uint32_t> v = {
        // 4 SC-distinguishing chars (汉语简业) + 4 shared CJK
        0x6C49, 0x8BED, 0x7B80, 0x4E1A,  // 汉 语 简 业
        0x4E2D, 0x6587, 0x4EBA, 0x5B57,  // 中 文 人 字
    };
    return v;
}

const std::vector<ScriptProfile>& GetScriptProfiles()
{
    static const std::vector<ScriptProfile> profiles = {
        // Chinese: TC and SC each have one entry; the script subtag (Hant/Hans)
        // is also the DirectWrite hint that distinguishes them — DirectWrite
        // maps plain "zh" to TC, so we MUST use the explicit script subtag.
        {L"zh-Hant", L"繁體中文",       TcProbes()},
        {L"zh-Hans", L"汉语简体",       ScProbes()},
        // Other CJK
        {L"ja",      L"日本語ひらがな", {0x3042,0x3044,0x30A2,0x30A4,0x65E5,0x672C,0x8A9E,0x6F22}},
        {L"ko",      L"한국어",         {0xAC00,0xB098,0xB2E4,0xD55C,0xAD6D,0xC5B4,0xC774,0xC77C}},
        // Other scripts
        {L"th",      L"ไทย",            {0x0E01,0x0E17,0x0E22,0x0E44,0x0E1B,0x0E23}},
        {L"vi",      L"Tiếng Việt",     {0x00E1,0x00E0,0x1EA1,0x1EBF,0x0103,0x0111}},
        {L"ar",      L"عربي",           {0x0627,0x0628,0x062A,0x0631,0x0639,0x064A}},
        {L"he",      L"עברית",          {0x05D0,0x05D1,0x05D2,0x05DE,0x05E9,0x05EA}},
        {L"ru",      L"Русский",        {0x0410,0x0411,0x0412,0x0420,0x0421,0x044F}},
        {L"el",      L"Ελληνικά",       {0x0391,0x0392,0x0395,0x03A9,0x03B1,0x03C9}},
    };
    return profiles;
}

// Find the profile matching the given locale. Returns nullptr if the locale
// doesn't match any script (e.g. en-US, fr-FR).
//
// Chinese needs region-aware classification: zh-CN/SG and bare "zh" → SC;
// zh-TW/HK/MO/Hant-* → TC. Other scripts use simple prefix match with
// a "-" subtag boundary so e.g. "ko" matches "ko-KR" but not "kok".
const ScriptProfile* LookupScriptProfile(const std::wstring& locale)
{
    auto find = [](const wchar_t* exact_prefix) -> const ScriptProfile* {
        for (const auto& p : GetScriptProfiles())
            if (_wcsicmp(p.locale_prefix, exact_prefix) == 0) return &p;
        return nullptr;
    };

    // Chinese region-aware mapping.
    if (locale.size() >= 2 && _wcsnicmp(locale.c_str(), L"zh", 2) == 0
        && (locale.size() == 2 || locale[2] == L'-' || locale[2] == L'_'))
    {
        bool is_tc = locale.find(L"-Hant") != std::wstring::npos
                  || locale.find(L"-TW")   != std::wstring::npos
                  || locale.find(L"-HK")   != std::wstring::npos
                  || locale.find(L"-MO")   != std::wstring::npos;
        return find(is_tc ? L"zh-Hant" : L"zh-Hans");
    }

    // Other scripts: prefix match with subtag boundary check.
    for (const auto& p : GetScriptProfiles()) {
        size_t plen = wcslen(p.locale_prefix);
        if (plen == 0) continue;
        if (locale.size() < plen) continue;
        if (_wcsnicmp(locale.c_str(), p.locale_prefix, plen) != 0) continue;
        if (locale.size() == plen || locale[plen] == L'-' || locale[plen] == L'_')
            return &p;
    }
    return nullptr;
}

// ============================================================
// SECTION 5 — ImGui atlas installation
// ============================================================

// Install a chain of matches as a single merged ImFont. Returns the primary
// ImFont* (py wrapped). matches is held by const ref AND iterated without
// moves — ImGui keeps the ranges pointer until Build() runs.
py::object InstallMatches(const std::vector<Win32FontMatch>& matches, float size_pixels)
{
    if (matches.empty()) return py::none();

    py::module_ imgui_mod = py::module_::import("pyimgui.imgui");
    py::object  fonts     = imgui_mod.attr("GetIO")().attr("Fonts");
    py::object  FontCfg   = imgui_mod.attr("ImFontConfig");
    py::object  primary   = py::none();

    for (size_t i = 0; i < matches.size(); ++i) {
        const auto& m = matches[i];
        py::object cfg = FontCfg();
        cfg.attr("FontNo") = m.face_index;
        if (i > 0) cfg.attr("MergeMode") = true;
        py::object f = fonts.attr("AddFontFromFileTTF")(
            WstrToUtf8(m.file_path),
            size_pixels,
            cfg,
            py::int_(reinterpret_cast<uintptr_t>(m.ranges.data())));
        if (i == 0) primary = f;
    }
    fonts.attr("Build")();
    return primary;
}

}  // anonymous namespace


// ============================================================
// SECTION 6 — Public API
// ============================================================

std::wstring GetUserLocale()
{
    wchar_t buf[LOCALE_NAME_MAX_LENGTH] = {0};
    int len = ::GetUserDefaultLocaleName(buf, LOCALE_NAME_MAX_LENGTH);
    if (len <= 0) return L"en-US";
    // wcsnlen handles both "len includes NUL" and "len excludes NUL" conventions.
    return std::wstring(buf, ::wcsnlen(buf, LOCALE_NAME_MAX_LENGTH));
}

std::vector<Win32FontMatch> MatchForSample(std::wstring sample_text,
                                            std::optional<std::wstring> locale_opt)
{
    std::vector<Win32FontMatch> result;
    if (sample_text.empty()) return result;

    std::wstring locale = locale_opt.value_or(GetUserLocale());

    ComPtr<IDWriteFont> font;
    if (!MapSampleWithHints(sample_text, locale, nullptr,
                             DWRITE_FONT_WEIGHT_REGULAR,
                             DWRITE_FONT_STYLE_NORMAL,
                             DWRITE_FONT_STRETCH_NORMAL, font))
        return result;

    Win32FontMatch m;
    if (BuildMatchFromFont(font.Get(), locale, m))
        result.push_back(std::move(m));
    return result;
}

// Build a multi-script fallback chain covering every entry in the script
// profile table. Each entry's `sample` + `locale_prefix` together force
// DirectWrite to pick a font appropriate for that script (so a single
// MatchForLocale("en-US") still pulls in Microsoft YaHei for SC, Yu Gothic
// UI for JP, Malgun Gothic for KR, etc., even though the user's locale
// itself doesn't request CJK).
//
// Chain order:
//   1. Latin (always)
//   2. User's primary script (if user locale matches a profile)
//   3. Every profile in table order (dedup'd against above)
//   4. Emoji (always)
std::vector<Win32FontMatch> MatchForLocale(std::optional<std::wstring> locale_opt)
{
    std::vector<Win32FontMatch> result;
    std::wstring user_locale = locale_opt.value_or(GetUserLocale());

    auto add = [&](const std::wstring& sample, const std::wstring& locale_hint) {
        ComPtr<IDWriteFont> font;
        if (!MapSampleWithHints(sample, locale_hint, nullptr,
                                 DWRITE_FONT_WEIGHT_REGULAR,
                                 DWRITE_FONT_STYLE_NORMAL,
                                 DWRITE_FONT_STRETCH_NORMAL, font))
            return;
        Win32FontMatch m;
        // Use the user's locale for family_name localisation regardless of hint.
        if (!BuildMatchFromFont(font.Get(), user_locale, m)) return;
        for (const auto& existing : result)
            if (existing.file_path == m.file_path && existing.face_index == m.face_index)
                return;
        result.push_back(std::move(m));
    };

    // 1. Latin — Windows UI default (Segoe UI on most systems).
    add(L"Aa", L"");

    // 2. User's primary script first, if it matches a known profile.
    const ScriptProfile* user_profile = LookupScriptProfile(user_locale);
    if (user_profile)
        add(user_profile->sample, std::wstring(user_profile->locale_prefix));

    // 3. Every other script in table order.
    for (const auto& p : GetScriptProfiles()) {
        if (&p == user_profile) continue;
        add(p.sample, std::wstring(p.locale_prefix));
    }

    // 4. Emoji — 😀 (U+1F600 as UTF-16 surrogate pair).
    add(L"\xD83D\xDE00", L"");

    return result;
}

Win32FontMatch GetSystemUiFont()
{
    Win32FontMatch out;

    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof(ncm);
    if (!::SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
        return out;

    std::wstring locale = GetUserLocale();
    std::wstring base_family(ncm.lfMessageFont.lfFaceName,
                             wcsnlen(ncm.lfMessageFont.lfFaceName, LF_FACESIZE));

    auto weight = static_cast<DWRITE_FONT_WEIGHT>(
        ncm.lfMessageFont.lfWeight ? ncm.lfMessageFont.lfWeight : DWRITE_FONT_WEIGHT_REGULAR);
    auto style  = ncm.lfMessageFont.lfItalic ? DWRITE_FONT_STYLE_ITALIC
                                              : DWRITE_FONT_STYLE_NORMAL;

    ComPtr<IDWriteFont> font;
    if (!MapSampleWithHints(L"Aa", locale,
                             base_family.empty() ? nullptr : base_family.c_str(),
                             weight, style, DWRITE_FONT_STRETCH_NORMAL, font))
        return out;

    if (!BuildMatchFromFont(font.Get(), locale, out))
        return out;

    // lfHeight: negative = em-pixels, positive = cell-pixels (incl. external leading).
    // We expose |h| as a hint; caller may override via Win32FontMatch.suggested_size.
    LONG h = ncm.lfMessageFont.lfHeight;
    out.suggested_size = static_cast<float>(h < 0 ? -h : h);
    return out;
}

std::vector<Win32FontInfo> ListFontsForLocale(std::wstring locale, float min_hit_ratio)
{
    std::vector<Win32FontInfo> result;
    auto& holder = GetFactory();

    ComPtr<IDWriteFontCollection> coll;
    if (FAILED(holder.factory->GetSystemFontCollection(coll.GetAddressOf(), FALSE)) || !coll)
        return result;

    if (locale.empty()) locale = GetUserLocale();
    const ScriptProfile* profile = LookupScriptProfile(locale);
    // Default Latin probes if locale doesn't match any script profile.
    static const std::vector<uint32_t> latin_default = {0x41, 0x42, 0x61, 0x62, 0x30, 0x39};
    const std::vector<uint32_t>& probes = profile ? profile->probes : latin_default;
    const size_t probe_n = probes.size();
    if (probe_n == 0) return result;

    // Pre-fetch the locale's primary font (for is_default_for_locale flag).
    std::wstring default_path;
    int default_face = -1;
    auto defaults = MatchForLocale(locale);
    if (!defaults.empty()) {
        // defaults[0] is Latin (Segoe UI); defaults[1] is the user's primary script
        // when LookupScriptProfile matched. For locales without a script match we
        // fall back to the Latin entry.
        size_t idx = (profile && defaults.size() > 1) ? 1 : 0;
        default_path = defaults[idx].file_path;
        default_face = defaults[idx].face_index;
    }

    UINT32 family_count = coll->GetFontFamilyCount();
    for (UINT32 i = 0; i < family_count; ++i) {
        ComPtr<IDWriteFontFamily> family;
        if (FAILED(coll->GetFontFamily(i, family.GetAddressOf())) || !family) continue;

        ComPtr<IDWriteFont> font;
        if (FAILED(family->GetFirstMatchingFont(
                DWRITE_FONT_WEIGHT_REGULAR,
                DWRITE_FONT_STRETCH_NORMAL,
                DWRITE_FONT_STYLE_NORMAL,
                font.GetAddressOf())) || !font)
            continue;

        int hits = 0;
        for (size_t k = 0; k < probe_n; ++k) {
            BOOL exists = FALSE;
            if (SUCCEEDED(font->HasCharacter(probes[k], &exists)) && exists)
                ++hits;
            // Short-circuit: stop probing if even all remaining hits can't reach threshold.
            size_t remaining = probe_n - k - 1;
            if (static_cast<float>(hits + remaining) / static_cast<float>(probe_n) < min_hit_ratio)
                break;
        }
        float ratio = static_cast<float>(hits) / static_cast<float>(probe_n);
        if (ratio < min_hit_ratio) continue;

        ComPtr<IDWriteFontFace> face;
        if (FAILED(font->CreateFontFace(face.GetAddressOf())) || !face) continue;

        Win32FontInfo info;
        if (!ResolveLocalFilePath(face.Get(), info.file_path, info.face_index)) continue;

        info.family_name = GetLocalizedFamilyName(family.Get(), locale);
        info.weight      = static_cast<int>(font->GetWeight());
        info.style       = static_cast<int>(font->GetStyle());
        info.hit_score   = hits;
        // "default" = DirectWrite's primary pick for this locale's script
        // (via MatchForLocale), NOT the highest-scoring candidate.
        info.is_default_for_locale =
            (!default_path.empty()
             && info.file_path == default_path
             && info.face_index == default_face);

        result.push_back(std::move(info));
    }

    std::sort(result.begin(), result.end(), [](const Win32FontInfo& a, const Win32FontInfo& b) {
        if (a.hit_score != b.hit_score) return a.hit_score > b.hit_score;
        return a.family_name < b.family_name;
    });
    return result;
}

std::optional<Win32FontMatch> MatchByFamily(std::wstring family_name,
                                            std::optional<std::wstring> locale_opt)
{
    if (family_name.empty()) return std::nullopt;
    std::wstring locale = locale_opt.value_or(GetUserLocale());

    auto& holder = GetFactory();
    ComPtr<IDWriteFontCollection> coll;
    if (FAILED(holder.factory->GetSystemFontCollection(coll.GetAddressOf(), FALSE)) || !coll)
        return std::nullopt;

    ComPtr<IDWriteFontFamily> family;

    // Fast path: FindFamilyName matches against the family's stored primary
    // name (typically en-US). Works for ASCII inputs like "Microsoft YaHei".
    UINT32 idx = 0;
    BOOL exists = FALSE;
    if (SUCCEEDED(coll->FindFamilyName(family_name.c_str(), &idx, &exists)) && exists)
        coll->GetFontFamily(idx, family.GetAddressOf());

    // Fallback: scan every family's localized names. ListFontsForLocale returns
    // localized family_name (e.g. "微软雅黑" on zh-CN systems), and feeding that
    // back into FindFamilyName fails — so we do an O(N*locales) sweep.
    if (!family) {
        UINT32 fam_count = coll->GetFontFamilyCount();
        for (UINT32 i = 0; i < fam_count && !family; ++i) {
            ComPtr<IDWriteFontFamily> candidate;
            if (FAILED(coll->GetFontFamily(i, candidate.GetAddressOf())) || !candidate) continue;
            ComPtr<IDWriteLocalizedStrings> names;
            if (FAILED(candidate->GetFamilyNames(names.GetAddressOf())) || !names) continue;
            UINT32 n = names->GetCount();
            for (UINT32 j = 0; j < n; ++j) {
                UINT32 nlen = 0;
                if (FAILED(names->GetStringLength(j, &nlen))) continue;
                std::wstring nm(static_cast<size_t>(nlen) + 1, L'\0');
                if (FAILED(names->GetString(j, nm.data(), nlen + 1))) continue;
                nm.resize(nlen);
                if (_wcsicmp(nm.c_str(), family_name.c_str()) == 0) {
                    family = candidate;
                    break;
                }
            }
        }
    }

    if (!family) return std::nullopt;

    ComPtr<IDWriteFont> font;
    if (FAILED(family->GetFirstMatchingFont(
            DWRITE_FONT_WEIGHT_REGULAR,
            DWRITE_FONT_STRETCH_NORMAL,
            DWRITE_FONT_STYLE_NORMAL,
            font.GetAddressOf())) || !font)
        return std::nullopt;

    Win32FontMatch m;
    if (!BuildMatchFromFont(font.Get(), locale, m))
        return std::nullopt;
    return m;
}

py::object AutoInstall(std::optional<std::wstring> locale_opt, float size_pixels)
{
    return InstallMatches(MatchForLocale(locale_opt), size_pixels);
}

py::object AutoInstallFamily(std::wstring family_name,
                              std::optional<std::wstring> locale_opt,
                              float size_pixels)
{
    auto primary = MatchByFamily(family_name, locale_opt);
    if (!primary) return py::none();

    std::vector<Win32FontMatch> chain;
    chain.push_back(std::move(*primary));

    // Append the auto-chain after the user-specified primary (dedup'd).
    auto auto_chain = MatchForLocale(locale_opt);
    for (auto& m : auto_chain) {
        bool seen = false;
        for (const auto& existing : chain)
            if (existing.file_path == m.file_path && existing.face_index == m.face_index) {
                seen = true; break;
            }
        if (!seen) chain.push_back(std::move(m));
    }
    return InstallMatches(chain, size_pixels);
}

py::object AutoInstallChain(std::vector<std::wstring> family_names,
                             std::optional<std::wstring> locale_opt,
                             float size_pixels)
{
    std::vector<Win32FontMatch> chain;
    chain.reserve(family_names.size());
    for (const auto& fam : family_names) {
        auto m = MatchByFamily(fam, locale_opt);
        if (m) chain.push_back(std::move(*m));
    }
    return InstallMatches(chain, size_pixels);
}

// ============================================================
// SECTION 7 — pybind11 bindings
// ============================================================

void pybind_setup_Win32Font(py::module_ m)
{
    py::class_<Win32FontMatch>(m, "Win32FontMatch")
        .def_property_readonly("file_path",   [](const Win32FontMatch& s) { return WstrToUtf8(s.file_path); })
        .def_readonly         ("face_index",  &Win32FontMatch::face_index)
        .def_property_readonly("family_name", [](const Win32FontMatch& s) { return WstrToUtf8(s.family_name); })
        .def_property_readonly("locale",      [](const Win32FontMatch& s) { return WstrToUtf8(s.locale); })
        .def_property_readonly("ranges",      [](const Win32FontMatch& s) { return s.ranges; })
        .def_readonly         ("suggested_size", &Win32FontMatch::suggested_size);

    py::class_<Win32FontInfo>(m, "Win32FontInfo")
        .def_property_readonly("family_name", [](const Win32FontInfo& s) { return WstrToUtf8(s.family_name); })
        .def_property_readonly("file_path",   [](const Win32FontInfo& s) { return WstrToUtf8(s.file_path); })
        .def_readonly         ("face_index",  &Win32FontInfo::face_index)
        .def_readonly         ("weight",      &Win32FontInfo::weight)
        .def_readonly         ("style",       &Win32FontInfo::style)
        .def_readonly         ("is_default_for_locale", &Win32FontInfo::is_default_for_locale)
        .def_readonly         ("hit_score",   &Win32FontInfo::hit_score);

    // Helper: convert an optional<string> argument to optional<wstring>.
    auto opt_w = [](const std::optional<std::string>& s) -> std::optional<std::wstring> {
        if (!s) return std::nullopt;
        return Utf8ToWstr(*s);
    };

    m.def("GetUserLocale", []() { return WstrToUtf8(GetUserLocale()); });

    m.def("MatchForLocale", [opt_w](std::optional<std::string> locale) {
        return MatchForLocale(opt_w(locale));
    }, py::arg("locale") = py::none());

    m.def("MatchForSample", [opt_w](std::string sample, std::optional<std::string> locale) {
        return MatchForSample(Utf8ToWstr(sample), opt_w(locale));
    }, py::arg("sample_text"), py::arg("locale") = py::none());

    m.def("GetSystemUiFont", &GetSystemUiFont);

    m.def("ListFontsForLocale", [](std::string locale, float min_hit_ratio) {
        return ListFontsForLocale(Utf8ToWstr(locale), min_hit_ratio);
    }, py::arg("locale"), py::arg("min_hit_ratio") = 0.5f);

    m.def("MatchByFamily", [opt_w](std::string family, std::optional<std::string> locale) {
        return MatchByFamily(Utf8ToWstr(family), opt_w(locale));
    }, py::arg("family_name"), py::arg("locale") = py::none());

    m.def("AutoInstall", [opt_w](std::optional<std::string> locale, float size_pixels) {
        return AutoInstall(opt_w(locale), size_pixels);
    }, py::arg("locale") = py::none(), py::arg("size_pixels") = 16.0f);

    m.def("AutoInstallFamily", [opt_w](std::string family, std::optional<std::string> locale, float size_pixels) {
        return AutoInstallFamily(Utf8ToWstr(family), opt_w(locale), size_pixels);
    }, py::arg("family_name"), py::arg("locale") = py::none(), py::arg("size_pixels") = 16.0f);

    m.def("AutoInstallChain", [opt_w](std::vector<std::string> families,
                                       std::optional<std::string> locale,
                                       float size_pixels) {
        std::vector<std::wstring> wfams;
        wfams.reserve(families.size());
        for (const auto& f : families) wfams.push_back(Utf8ToWstr(f));
        return AutoInstallChain(std::move(wfams), opt_w(locale), size_pixels);
    }, py::arg("family_names"), py::arg("locale") = py::none(), py::arg("size_pixels") = 16.0f);

    // snake_case aliases for the three high-traffic installers.
    m.attr("auto_install")         = m.attr("AutoInstall");
    m.attr("auto_install_family")  = m.attr("AutoInstallFamily");
    m.attr("auto_install_chain")   = m.attr("AutoInstallChain");
}

}
END_WIN32FONT_NAMESPACE
