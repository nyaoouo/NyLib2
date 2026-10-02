#include "./Win32Hook.h"

#include <atomic>
#include <mutex>
#include <vector>

START_M_IMGUI_IMPL_WIN32_NAMESPACE
{
    using OVERLAY_TYPES_NAMESPACE::InputPolicy;

    static std::atomic<WNDPROC> oWndProc{nullptr};
    static std::atomic<bool> inputEnabled{false};
    static std::atomic<int> handlersInFlight{0};
    // The attached inbound's inputPolicy; dereferenced only inside the in-flight section.
    static std::atomic<std::atomic<int> *> attachedPolicy{nullptr};
    static HWND chainedHwnd = nullptr;
    static std::mutex chainMutex;

    enum class MessageClass
    {
        Other,
        Mouse,
        Keyboard,
    };

    static MessageClass ClassifyMessage(UINT uMsg)
    {
        switch (uMsg)
        {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_RBUTTONDBLCLK:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_MBUTTONDBLCLK:
        case WM_XBUTTONDOWN:
        case WM_XBUTTONUP:
        case WM_XBUTTONDBLCLK:
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            return MessageClass::Mouse;
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
        case WM_CHAR:
        case WM_SYSCHAR:
        case WM_DEADCHAR:
        case WM_SYSDEADCHAR:
        case WM_UNICHAR:
            return MessageClass::Keyboard;
        }
        return MessageClass::Other;
    }

    struct MessageRoute
    {
        bool handlerCalled = false;
        bool swallowed = false;
    };

    // Routes one message under `policy`: whether ImGui's handler saw it and whether the game is denied it.
    static MessageRoute HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, InputPolicy policy)
    {
        MessageRoute route;
        if (ImGui::GetCurrentContext() == nullptr)
            return route;
        MessageClass messageClass = ClassifyMessage(uMsg);
        if (policy == InputPolicy::PassAll)
        {
            if (messageClass == MessageClass::Other && uMsg != WM_SETCURSOR)
            {
                ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
                route.handlerCalled = true;
            }
            return route;
        }

        route.handlerCalled = true;
        if (ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam) != 0)
            route.swallowed = true;
        else if (policy == InputPolicy::CaptureAll)
            route.swallowed = messageClass != MessageClass::Other;
        else if (messageClass == MessageClass::Mouse)
            route.swallowed = ImGui::GetIO().WantCaptureMouse;
        else if (messageClass == MessageClass::Keyboard)
            route.swallowed = ImGui::GetIO().WantCaptureKeyboard;
        return route;
    }

    // A button or key DOWN and the sides it reached that have not seen its UP yet.
    struct HeldInput
    {
        UINT message = 0;
        WPARAM wParam = 0;
        LPARAM lParam = 0;
        bool imgui = false;
        bool game = false;
    };

    struct SyntheticUp
    {
        UINT message;
        WPARAM wParam;
        LPARAM lParam;
        bool toImGui;
        bool toGame;
    };

    // Bumped by Attach; the window thread then drops its held state without synthesizing.
    static std::atomic<unsigned> attachGeneration{0};
    // Window-thread-only state, touched by hkWindowProc alone.
    static unsigned observedGeneration = 0;
    static InputPolicy observedPolicy = InputPolicy::Auto;
    static HeldInput heldButtons[5];
    static HeldInput heldKeys[256];

    // The held entry a button or key DOWN/UP refers to, or nullptr for any other message.
    static HeldInput *FindHeld(UINT uMsg, WPARAM wParam)
    {
        switch (uMsg)
        {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONDBLCLK:
        case WM_LBUTTONUP:
            return &heldButtons[0];
        case WM_RBUTTONDOWN:
        case WM_RBUTTONDBLCLK:
        case WM_RBUTTONUP:
            return &heldButtons[1];
        case WM_MBUTTONDOWN:
        case WM_MBUTTONDBLCLK:
        case WM_MBUTTONUP:
            return &heldButtons[2];
        case WM_XBUTTONDOWN:
        case WM_XBUTTONDBLCLK:
        case WM_XBUTTONUP:
            return &heldButtons[GET_XBUTTON_WPARAM(wParam) == XBUTTON1 ? 3 : 4];
        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYUP:
            return wParam < 256 ? &heldKeys[wParam] : nullptr;
        }
        return nullptr;
    }

    // Records that one side received a button or key message; an UP releases that side.
    static void RecordDelivery(UINT uMsg, WPARAM wParam, LPARAM lParam, bool toImGui)
    {
        HeldInput *held = FindHeld(uMsg, wParam);
        if (held == nullptr)
            return;
        bool &side = toImGui ? held->imgui : held->game;
        bool isUp = uMsg == WM_LBUTTONUP || uMsg == WM_RBUTTONUP || uMsg == WM_MBUTTONUP ||
                    uMsg == WM_XBUTTONUP || uMsg == WM_KEYUP || uMsg == WM_SYSKEYUP;
        if (isUp)
        {
            side = false;
            return;
        }
        held->message = uMsg;
        held->wParam = wParam;
        held->lParam = lParam;
        side = true;
    }

    static SyntheticUp MakeUp(const HeldInput &held, bool toImGui, bool toGame)
    {
        UINT up;
        WORD mk;
        switch (held.message)
        {
        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
            return {held.message == WM_KEYDOWN ? (UINT)WM_KEYUP : (UINT)WM_SYSKEYUP, held.wParam, held.lParam | (LPARAM)0xC0000000, toImGui, toGame};
        case WM_LBUTTONDOWN:
        case WM_LBUTTONDBLCLK:
            up = WM_LBUTTONUP;
            mk = MK_LBUTTON;
            break;
        case WM_RBUTTONDOWN:
        case WM_RBUTTONDBLCLK:
            up = WM_RBUTTONUP;
            mk = MK_RBUTTON;
            break;
        case WM_MBUTTONDOWN:
        case WM_MBUTTONDBLCLK:
            up = WM_MBUTTONUP;
            mk = MK_MBUTTON;
            break;
        default:
            up = WM_XBUTTONUP;
            mk = GET_XBUTTON_WPARAM(held.wParam) == XBUTTON1 ? MK_XBUTTON1 : MK_XBUTTON2;
            break;
        }
        WORD xButton = up == WM_XBUTTONUP ? GET_XBUTTON_WPARAM(held.wParam) : 0;
        return {up, MAKEWPARAM(GET_KEYSTATE_WPARAM(held.wParam) & ~mk, xButton), held.lParam, toImGui, toGame};
    }

    // On an attachment or policy change, releases held DOWNs from every side that loses the stream.
    // Clears those sides before returning, so a re-entrant message sees the state the UPs will produce.
    static void SyncPolicy(InputPolicy policy, unsigned generation, std::vector<SyntheticUp> &ups)
    {
        if (generation != observedGeneration)
        {
            observedGeneration = generation;
            observedPolicy = policy;
            for (HeldInput &held : heldButtons)
                held = HeldInput();
            for (HeldInput &held : heldKeys)
                held = HeldInput();
            return;
        }
        if (policy == observedPolicy)
            return;
        observedPolicy = policy;
        bool imguiLoses = policy == InputPolicy::PassAll;
        bool gameLosesMouse = policy == InputPolicy::CaptureAll;
        bool gameLosesKeys = policy == InputPolicy::CaptureAll;
        if (policy == InputPolicy::Auto && ImGui::GetCurrentContext() != nullptr)
        {
            gameLosesMouse = ImGui::GetIO().WantCaptureMouse;
            gameLosesKeys = ImGui::GetIO().WantCaptureKeyboard;
        }
        auto release = [&](HeldInput &held, bool gameLoses)
        {
            bool toImGui = held.imgui && imguiLoses;
            bool toGame = held.game && gameLoses;
            if (!toImGui && !toGame)
                return;
            ups.push_back(MakeUp(held, toImGui, toGame));
            held.imgui = held.imgui && !toImGui;
            held.game = held.game && !toGame;
        };
        for (HeldInput &held : heldButtons)
            release(held, gameLosesMouse);
        for (HeldInput &held : heldKeys)
            release(held, gameLosesKeys);
    }

    static LRESULT CALLBACK hkWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
    {
        handlersInFlight++;
        MessageRoute route;
        bool routed = false;
        std::vector<SyntheticUp> ups;
        if (inputEnabled)
        {
            std::atomic<int> *source = attachedPolicy;
            unsigned generation = attachGeneration;
            InputPolicy policy = source != nullptr ? (InputPolicy)source->load() : InputPolicy::Auto;
            SyncPolicy(policy, generation, ups);
            for (const SyntheticUp &up : ups)
                if (up.toImGui)
                    ImGui_ImplWin32_WndProcHandler(hwnd, up.message, up.wParam, up.lParam);
            route = HandleMessage(hwnd, uMsg, wParam, lParam, policy);
            routed = true;
            if (route.handlerCalled)
                RecordDelivery(uMsg, wParam, lParam, true);
        }
        handlersInFlight--;
        for (const SyntheticUp &up : ups)
            if (up.toGame)
                ::CallWindowProc(oWndProc, hwnd, up.message, up.wParam, up.lParam);
        if (route.swallowed)
            return (uMsg == WM_UNICHAR && wParam == UNICODE_NOCHAR) ? 0L : 1L;
        if (routed)
            RecordDelivery(uMsg, wParam, lParam, false);
        return ::CallWindowProc(oWndProc, hwnd, uMsg, wParam, lParam);
    }

    void Attach(HWND hwnd, std::atomic<int> *policySource)
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        if (chainedHwnd != nullptr && !::IsWindow(chainedHwnd))
            chainedHwnd = nullptr;
        if (chainedHwnd == hwnd)
        {
            attachGeneration++;
            attachedPolicy = policySource;
            inputEnabled = true;
            return;
        }
        if (chainedHwnd != nullptr)
            _throwV_("window procedure is still chained on another window: {:#x}", (uintptr_t)chainedHwnd);
        oWndProc = (WNDPROC)::GetWindowLongPtr(hwnd, GWLP_WNDPROC);
        WNDPROC previous = (WNDPROC)::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)hkWindowProc);
        if (previous == nullptr)
            _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
        oWndProc = previous;
        chainedHwnd = hwnd;
        attachGeneration++;
        attachedPolicy = policySource;
        inputEnabled = true;
    }

    // Waits for hook bodies on other threads; a no-op on the window's own thread.
    static void WaitForHandlers(HWND hwnd)
    {
        if (::GetWindowThreadProcessId(hwnd, nullptr) == ::GetCurrentThreadId())
            return;
        MSG msg;
        while (handlersInFlight != 0)
        {
            ::MsgWaitForMultipleObjects(0, nullptr, FALSE, 1, QS_SENDMESSAGE);
            ::PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
        }
    }

    // Restores the window procedure only while ours is on top; otherwise stays chained as a pass-through.
    // On return, even by exception, no other thread still reads the policy source.
    void Detach(HWND hwnd)
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        attachedPolicy = nullptr;
        inputEnabled = false;
        try
        {
            if (chainedHwnd == hwnd && (WNDPROC)::GetWindowLongPtr(hwnd, GWLP_WNDPROC) == hkWindowProc)
            {
                if (::SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc.load()) == 0)
                    _throwV_("SetWindowLongPtr failed: {}", ::GetLastError());
                chainedHwnd = nullptr;
            }
        }
        catch (...)
        {
            WaitForHandlers(hwnd);
            throw;
        }
        WaitForHandlers(hwnd);
    }
}
END_M_IMGUI_IMPL_WIN32_NAMESPACE