#include "./Impl_Win32.h"
START_M_IMGUI_IMPL_WIN32_NAMESPACE
{
	static WNDPROC oWndProc = NULL;

	static LRESULT CALLBACK hkWindowProc(
		_In_ HWND hwnd,
		_In_ UINT uMsg,
		_In_ WPARAM wParam,
		_In_ LPARAM lParam)
	{
		if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) > 0)
			return 1L;
		return ::CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
	}

	void Attach(HWND hwnd)
	{
		if ((oWndProc = (WNDPROC)::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)hkWindowProc)) == NULL)
			_throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
	}

	void Detach(HWND hwnd)
	{
		if (::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc) == NULL)
			_throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
		oWndProc = NULL;
	}
}
END_M_IMGUI_IMPL_WIN32_NAMESPACE