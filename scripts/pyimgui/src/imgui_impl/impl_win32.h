#include "../gheader.h"

IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace mImguiImpl
{
    namespace impl_win32
    {
        void init(HWND hwnd);
        void uninit(HWND hwnd);
    }
}