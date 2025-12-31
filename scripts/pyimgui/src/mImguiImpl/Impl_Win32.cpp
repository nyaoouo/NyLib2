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
		
        if (M_IMGUI_HELPER_NAMESPACE::Win32TrayWindowProc(hwnd, uMsg, wParam, lParam))
            return 1L;
		if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) > 0)
			return 1L;
		
		// dont pass mouse and keyboard events if imgui is capturing

		//mouses
		switch (uMsg)
		{
		case WM_LBUTTONDOWN:
		case WM_LBUTTONUP:
		case WM_RBUTTONDOWN:
		case WM_RBUTTONUP:
		case WM_MBUTTONDOWN:
		case WM_MBUTTONUP:
		case WM_XBUTTONDOWN:
		case WM_XBUTTONUP:
		case WM_MOUSEWHEEL:
		case WM_MOUSEHWHEEL:
			if (igGetIO()->WantCaptureMouse)
				return 1L;
			break;
		case WM_KEYDOWN:
		case WM_KEYUP:
		case WM_SYSKEYDOWN:
		case WM_SYSKEYUP:
		case WM_CHAR:
			if (igGetIO()->WantCaptureKeyboard)
				return 1L;
			break;
		}
		


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