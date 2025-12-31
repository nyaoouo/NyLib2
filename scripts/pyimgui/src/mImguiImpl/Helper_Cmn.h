#pragma once
#include "../gHeader.h"
#define STB_IMAGE_STATIC
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include <shellapi.h>
#pragma comment(lib, "Shell32.lib")

#define M_IMGUI_HELPER_NAMESPACE mNameSpace::MImguiHelper
#define START_M_IMGUI_HELPER_NAMESPACE \
    namespace mNameSpace               \
    {                                  \
        namespace MImguiHelper
#define END_M_IMGUI_HELPER_NAMESPACE }

START_M_IMGUI_HELPER_NAMESPACE
{
    static HICON defaultIcon = LoadIconW(nullptr, IDI_APPLICATION);
    LRESULT CALLBACK Win32TrayWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static UINT WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    class Win32TrayIconHelper
    {
    private:
        HWND hwnd = nullptr;
        NOTIFYICONDATAW nid = {};
        bool inTray = false;
    public:
        std::wstring tooltip = L"";
        HICON hIcon = defaultIcon;
        
        void HideToTray();
        void RestoreFromTray();
        void UpdateInfo(const std::wstring &tooltip, const std::wstring &iconPath = L"");
        void SetHwnd(HWND hwnd);
        LRESULT _WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    private:
        BOOL AddIcon();
        BOOL RemoveIcon();
    };
}
END_M_IMGUI_HELPER_NAMESPACE