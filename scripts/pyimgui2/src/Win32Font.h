#pragma once
#include "./gHeader.h"

#include <optional>
#include <string>
#include <vector>

#define WIN32FONT_NAMESPACE mNameSpace::Win32Font
#define START_WIN32FONT_NAMESPACE \
    namespace mNameSpace          \
    {                             \
        namespace Win32Font
#define END_WIN32FONT_NAMESPACE }

START_WIN32FONT_NAMESPACE
{
    // ---- public types ----

    struct Win32FontMatch
    {
        std::wstring file_path;
        int          face_index = 0;
        std::wstring family_name;
        std::wstring locale;
        std::vector<ImWchar> ranges;   // ends with 0 sentinel
        float        suggested_size = 0.0f;
    };

    struct Win32FontInfo
    {
        std::wstring family_name;
        std::wstring file_path;
        int          face_index = 0;
        int          weight = 0;       // DWRITE_FONT_WEIGHT
        int          style = 0;        // DWRITE_FONT_STYLE
        bool         is_default_for_locale = false;
        int          hit_score = 0;
    };

    // ---- automatic matching ----
    // On failure these return an empty container / default-constructed match.
    // Callers detect failure via empty vector or empty Win32FontMatch.file_path.
    std::vector<Win32FontMatch> MatchForLocale(std::optional<std::wstring> locale);
    std::vector<Win32FontMatch> MatchForSample(std::wstring sample_text,
                                               std::optional<std::wstring> locale);
    Win32FontMatch GetSystemUiFont();
    std::wstring   GetUserLocale();

    // ---- enumeration + switching ----
    std::vector<Win32FontInfo> ListFontsForLocale(std::wstring locale, float min_hit_ratio);
    std::optional<Win32FontMatch> MatchByFamily(std::wstring family_name,
                                                std::optional<std::wstring> locale);

    // ---- one-shot installers ----
    // All AutoInstall* variants return the primary ImFont* (as py::object) on
    // success, or py::none() on failure. They call into pyimgui.imgui to do
    // AddFontFromFileTTF + Build; require an active ImGui context.
    py::object AutoInstall(std::optional<std::wstring> locale, float size_pixels);
    py::object AutoInstallFamily(std::wstring family_name,
                                 std::optional<std::wstring> locale,
                                 float size_pixels);
    // User-specified chain: install fonts in the given order. Families that
    // can't be resolved (MatchByFamily fails) are silently skipped. If no
    // family resolves, returns py::none().
    py::object AutoInstallChain(std::vector<std::wstring> family_names,
                                std::optional<std::wstring> locale,
                                float size_pixels);

    void pybind_setup_Win32Font(py::module_ m);
}
END_WIN32FONT_NAMESPACE
