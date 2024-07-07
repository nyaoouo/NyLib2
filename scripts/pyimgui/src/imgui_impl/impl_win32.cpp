#include "./impl_win32.h"

static WNDPROC oWndProc = NULL;

static LRESULT CALLBACK hkWindowProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) > 0)
		return 1L;	
	return ::CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
}

void mImguiImpl::impl_win32::init(HWND hwnd)
{
	oWndProc = (WNDPROC)::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)hkWindowProc);
}
void mImguiImpl::impl_win32::uninit(HWND hwnd)
{
	::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc);
	oWndProc = NULL;
}