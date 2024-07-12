#include "./ImguiInbound.h"
START_IMGUI_INBOUND_NAMESPACE
{
    static RenderType g_renderType = RenderType::None;
    static PVOID *g_methodsTable = NULL;
    static size_t g_methodsTableSize = 0;

    RenderType GuessRenderType()
    {
        HANDLE h = NULL;
        if ((h = ::GetModuleHandle(_T("d3d9.dll"))) != NULL)
        {
            dbgPrint("[+] RenderType D3D9, handle: %llx\n", (uint64_t)h);
            return RenderType::D3D9;
        }
        else if ((h = ::GetModuleHandle(_T("d3d10.dll"))) != NULL)
        {
            dbgPrint("[+] RenderType D3D10, handle: %llx\n", (uint64_t)h);
            return RenderType::D3D10;
        }
        else if ((h = ::GetModuleHandle(_T("d3d11.dll"))) != NULL)
        {
            dbgPrint("[+] RenderType D3D11, handle: %llx\n", (uint64_t)h);
            return RenderType::D3D11;
        }
        else if ((h = ::GetModuleHandle(_T("d3d12.dll"))) != NULL)
        {
            dbgPrint("[+] RenderType D3D12, handle: %llx\n", (uint64_t)h);
            return RenderType::D3D12;
        }
        else
        {
            dbgPrint("RenderType Unknown\n");
            return RenderType::Unknown;
        }
    }

    RenderType GetRenderType()
    {
        if (g_renderType == RenderType::None || g_renderType == RenderType::Auto)
        {
            Init(GuessRenderType());
        }
        return g_renderType;
    }

    PVOID GetMethod(size_t index)
    {
        if (g_methodsTable == NULL || index >= g_methodsTableSize)
        {
            _throwV_("Method table is not initialized or index out of range: {}", index);
        }
        return g_methodsTable[index];
    }

#ifdef _mEBreak_
#error _mEBreak_ already defined
#endif
#ifdef _mSBreak_
#error _mSBreak_ already defined
#endif
#ifdef _mInitMethodsTable_
#error _mInitMethodsTable_ already defined
#endif
#ifdef _mSetMethodsTable_
#error _mSetMethodsTable_ already defined
#endif

#define _mEBreak_(x, ...)             \
    {                                 \
        err = _errV_(x, __VA_ARGS__); \
        break;                        \
    }
#define _mSBreak_()      \
    {                    \
        bSuccess = true; \
        break;           \
    }
#define _mInitMethodsTable_(size)                                             \
    {                                                                         \
        if (g_methodsTable != NULL)                                           \
            free(g_methodsTable);                                             \
        g_methodsTableSize = (size);                                          \
        g_methodsTable = (PVOID *)malloc(g_methodsTableSize * sizeof(PVOID)); \
    }
#define _mSetMethodsTable_(offset, src, size)                                        \
    {                                                                                \
        memcpy(g_methodsTable + (offset), *(PVOID **)(src), (size) * sizeof(PVOID)); \
    }

    void Init(RenderType renderType)
    {
        bool bSuccess = false;
        HRESULT hr = S_OK;
        std::runtime_error err = _err_("Failed but no error message");

        if (renderType == RenderType::None || renderType == RenderType::Auto)
        {
            dbgPrint("[!] RenderType pass to Init is None or Auto, please use Init(GuessRenderType()) instead\n");
            renderType = GuessRenderType();
        }

        dbgPrint("[+] Init RenderType: %d\n", renderType);

        switch (renderType)
        {
        case RenderType::D3D9:
        case RenderType::D3D10:
        case RenderType::D3D11:
        case RenderType::D3D12:
        {
            WNDCLASSEX TestWndClass;
            TestWndClass.cbSize = sizeof(WNDCLASSEX);
            TestWndClass.style = CS_HREDRAW | CS_VREDRAW;
            TestWndClass.lpfnWndProc = DefWindowProc;
            TestWndClass.cbClsExtra = 0;
            TestWndClass.cbWndExtra = 0;
            TestWndClass.hInstance = GetModuleHandle(NULL);
            TestWndClass.hIcon = NULL;
            TestWndClass.hCursor = NULL;
            TestWndClass.hbrBackground = NULL;
            TestWndClass.lpszMenuName = NULL;
            TestWndClass.lpszClassName = _T("ImguiInternalTestWndClass");
            TestWndClass.hIconSm = NULL;
            ::RegisterClassEx(&TestWndClass);

            HWND TestWnd = ::CreateWindow(
                TestWndClass.lpszClassName,
                _T("ImguiInternalTestWnd"),
                WS_OVERLAPPEDWINDOW,
                0, 0, 100, 100,
                NULL, NULL, TestWndClass.hInstance, NULL);

            switch (renderType)
            {
            case RenderType::D3D9:
            {
                HMODULE libD3D9;
                if ((libD3D9 = ::GetModuleHandle(_T("d3d9.dll"))) == NULL)
                {
                    _mEBreak_("Failed to get d3d9.dll handle, GetLastError: {}", ::GetLastError());
                }

                void *Direct3DCreate9;
                if ((Direct3DCreate9 = ::GetProcAddress(libD3D9, "Direct3DCreate9")) == NULL)
                {
                    _mEBreak_("Failed to get Direct3DCreate9 address, GetLastError: {}", ::GetLastError());
                }

                LPDIRECT3D9 direct3D9;
                if ((direct3D9 = ((LPDIRECT3D9(WINAPI *)(UINT))(Direct3DCreate9))(D3D_SDK_VERSION)) == NULL)
                {
                    _mEBreak_("Failed to create Direct3D9 object", 0);
                }

                do
                {
                    D3DPRESENT_PARAMETERS d3dpp;
                    d3dpp.BackBufferWidth = 0;
                    d3dpp.BackBufferHeight = 0;
                    d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
                    d3dpp.BackBufferCount = 0;
                    d3dpp.MultiSampleType = D3DMULTISAMPLE_NONE;
                    d3dpp.MultiSampleQuality = 0;
                    d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
                    d3dpp.hDeviceWindow = TestWnd;
                    d3dpp.Windowed = TRUE;
                    d3dpp.EnableAutoDepthStencil = FALSE;
                    d3dpp.AutoDepthStencilFormat = D3DFMT_UNKNOWN;
                    d3dpp.Flags = 0;
                    d3dpp.FullScreen_RefreshRateInHz = 0;
                    d3dpp.PresentationInterval = 0;

                    LPDIRECT3DDEVICE9 device;
                    if ((hr = direct3D9->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, TestWnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_DISABLE_DRIVER_MANAGEMENT, &d3dpp, &device)) != D3D_OK)
                    {
                        _mEBreak_("Failed to create Direct3D9 device, Result: {}", hr);
                    }
                    _mInitMethodsTable_(119);
                    _mSetMethodsTable_(0, device, 119);
                    device->Release();
                } while (0);
                direct3D9->Release();
                _mSBreak_();
            }
            case RenderType::D3D10:
            {
                HMODULE libDXGI, libD3D10;
                if ((libDXGI = ::GetModuleHandle(_T("dxgi.dll"))) == NULL)
                {
                    _mEBreak_("Failed to get dxgi.dll handle, GetLastError: {}", ::GetLastError());
                }
                if ((libD3D10 = ::GetModuleHandle(_T("d3d10.dll"))) == NULL)
                {
                    _mEBreak_("Failed to get d3d10.dll handle, GetLastError: {}", ::GetLastError());
                }
                PVOID CreateDXGIFactory, mD3D10CreateDeviceAndSwapChain;
                if ((CreateDXGIFactory = ::GetProcAddress(libDXGI, "CreateDXGIFactory")) == NULL)
                {
                    _mEBreak_("Failed to get CreateDXGIFactory address, GetLastError: {}", ::GetLastError());
                }
                if ((mD3D10CreateDeviceAndSwapChain = ::GetProcAddress(libD3D10, "D3D10CreateDeviceAndSwapChain")) == NULL)
                {
                    _mEBreak_("Failed to get D3D10CreateDeviceAndSwapChain address, GetLastError: {}", ::GetLastError());
                }

                IDXGIFactory *dxgiFactory;
                if ((hr = ((HRESULT(WINAPI *)(REFIID, void **))(CreateDXGIFactory))(IID_PPV_ARGS(&dxgiFactory))) != S_OK)
                {
                    _mEBreak_("Failed to create IDXGIFactory object, Result: {}", hr);
                }

                do
                {
                    IDXGIAdapter *adapter;
                    if ((hr = dxgiFactory->EnumAdapters(0, &adapter)) != S_OK)
                    {
                        _mEBreak_("Failed to enumerate adapter, Result: {}", hr);
                    }
                    do
                    {
                        DXGI_RATIONAL refreshRate = {60, 1};
                        DXGI_MODE_DESC bufferDesc = {100, 100, refreshRate, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED};
                        DXGI_SAMPLE_DESC sampleDesc = {1, 0};
                        DXGI_SWAP_CHAIN_DESC swapChainDesc = {bufferDesc, sampleDesc, DXGI_USAGE_RENDER_TARGET_OUTPUT, 1, TestWnd, TRUE, DXGI_SWAP_EFFECT_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH};

                        IDXGISwapChain *swapChain;
                        ID3D10Device *device;
                        if ((hr = ((HRESULT(WINAPI *)(IDXGIAdapter *, D3D10_DRIVER_TYPE, HMODULE, UINT, UINT, DXGI_SWAP_CHAIN_DESC *, IDXGISwapChain **, ID3D10Device **))(mD3D10CreateDeviceAndSwapChain))(
                                 adapter, D3D10_DRIVER_TYPE_HARDWARE, NULL, 0, D3D10_SDK_VERSION, &swapChainDesc, &swapChain, &device)) != S_OK)
                        {
                            _mEBreak_("Failed to create D3D10 device and swap chain, Result: {}", hr);
                        }

                        _mInitMethodsTable_(18 + 98);
                        _mSetMethodsTable_(0, swapChain, 18);
                        _mSetMethodsTable_(18, device, 98);

                        swapChain->Release();
                        device->Release();
                        _mSBreak_();
                    } while (0);
                    adapter->Release();
                } while (0);
                dxgiFactory->Release();
            }
            case RenderType::D3D11:
            {
                HMODULE libD3D11;
                if ((libD3D11 = ::GetModuleHandle(_T("d3d11.dll"))) == NULL)
                {
                    _mEBreak_("Failed to get d3d11.dll handle, GetLastError: {}", ::GetLastError());
                }
                PVOID D3D11CreateDeviceAndSwapChain;
                if ((D3D11CreateDeviceAndSwapChain = ::GetProcAddress(libD3D11, "D3D11CreateDeviceAndSwapChain")) == NULL)
                {
                    _mEBreak_("Failed to get D3D11CreateDeviceAndSwapChain address, GetLastError: {}", ::GetLastError());
                }
                D3D_FEATURE_LEVEL featureLevel;
                IDXGISwapChain *swapChain;
                ID3D11Device *device;
                ID3D11DeviceContext *context;
                const D3D_FEATURE_LEVEL featureLevels[] = {D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0};
                DXGI_RATIONAL refreshRate = {60, 1};
                DXGI_MODE_DESC bufferDesc = {100, 100, refreshRate, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED};
                DXGI_SAMPLE_DESC sampleDesc = {1, 0};
                DXGI_SWAP_CHAIN_DESC swapChainDesc = {bufferDesc, sampleDesc, DXGI_USAGE_RENDER_TARGET_OUTPUT, 1, TestWnd, TRUE, DXGI_SWAP_EFFECT_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH};
                if ((hr = ((HRESULT(WINAPI *)(_In_opt_ IDXGIAdapter *, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL *, UINT, UINT, const DXGI_SWAP_CHAIN_DESC *, IDXGISwapChain **, ID3D11Device **, D3D_FEATURE_LEVEL *, ID3D11DeviceContext **))(D3D11CreateDeviceAndSwapChain))(
                         NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, featureLevels, 2, D3D11_SDK_VERSION, &swapChainDesc, &swapChain, &device, &featureLevel, &context)) != S_OK)
                {
                    _mEBreak_("Failed to create D3D11 device and swap chain, Result: {}", hr);
                }

                _mInitMethodsTable_(18 + 43 + 144);
                _mSetMethodsTable_(0, swapChain, 18);
                _mSetMethodsTable_(18, device, 43);
                _mSetMethodsTable_(18 + 43, context, 144);
                swapChain->Release();
                device->Release();
                context->Release();
                _mSBreak_();
            }
            case RenderType::D3D12:
            {
                HMODULE libDXGI, libD3D12;
                if ((libDXGI = ::GetModuleHandle(_T("dxgi.dll"))) == NULL)
                {
                    _mEBreak_("Failed to get dxgi.dll handle, GetLastError: {}", ::GetLastError());
                }
                if ((libD3D12 = ::GetModuleHandle(_T("d3d12.dll"))) == NULL)
                {
                    _mEBreak_("Failed to get d3d12.dll handle, GetLastError: {}", ::GetLastError());
                }
                PVOID CreateDXGIFactory, D3D12CreateDevice;
                if ((CreateDXGIFactory = ::GetProcAddress(libDXGI, "CreateDXGIFactory")) == NULL)
                {
                    _mEBreak_("Failed to get CreateDXGIFactory address, GetLastError: {}", ::GetLastError());
                }
                if ((D3D12CreateDevice = ::GetProcAddress(libD3D12, "D3D12CreateDevice")) == NULL)
                {
                    _mEBreak_("Failed to get D3D12CreateDevice address, GetLastError: {}", ::GetLastError());
                }
                IDXGIFactory *dxgiFactory;
                if ((hr = ((HRESULT(WINAPI *)(REFIID, void **))(CreateDXGIFactory))(IID_PPV_ARGS(&dxgiFactory))) != S_OK)
                {
                    _mEBreak_("Failed to create IDXGIFactory object, Result: {}", hr);
                }
                do
                {
                    IDXGIAdapter *adapter;
                    if ((hr = dxgiFactory->EnumAdapters(0, &adapter)) != S_OK)
                    {
                        _mEBreak_("Failed to enumerate adapter, Result: {}", hr);
                    }
                    do
                    {
                        ID3D12Device *device;
                        if ((hr = ((HRESULT(WINAPI *)(IUnknown *, D3D_FEATURE_LEVEL, REFIID, void **))(D3D12CreateDevice))(
                                 adapter, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), (void **)&device)) != S_OK)
                            _mEBreak_("Failed to create D3D12 device, Result: {}", hr);
                        do
                        {
                            ID3D12CommandQueue *commandQueue;
                            D3D12_COMMAND_QUEUE_DESC queueDesc = {D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0};
                            if ((hr = device->CreateCommandQueue(&queueDesc, __uuidof(ID3D12CommandQueue), (void **)&commandQueue)) != S_OK)
                                _mEBreak_("Failed to create D3D12 command queue, Result: {}", hr);
                            do
                            {
                                ID3D12CommandAllocator *commandAllocator;
                                if ((hr = device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, __uuidof(ID3D12CommandAllocator), (void **)&commandAllocator)) != S_OK)
                                    _mEBreak_("Failed to create D3D12 command allocator, Result: {}", hr);
                                do
                                {
                                    ID3D12GraphicsCommandList *commandList;
                                    if ((hr = device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, commandAllocator, NULL, __uuidof(ID3D12GraphicsCommandList), (void **)&commandList)) != S_OK)
                                        _mEBreak_("Failed to create D3D12 command list, Result: {}", hr);
                                    do
                                    {
                                        DXGI_RATIONAL refreshRate = {60, 1};
                                        DXGI_MODE_DESC bufferDesc = {100, 100, refreshRate, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED};
                                        DXGI_SAMPLE_DESC sampleDesc = {1, 0};
                                        DXGI_SWAP_CHAIN_DESC swapChainDesc = {bufferDesc, sampleDesc, DXGI_USAGE_RENDER_TARGET_OUTPUT, 2, TestWnd, TRUE, DXGI_SWAP_EFFECT_FLIP_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH};
                                        IDXGISwapChain *swapChain;
                                        if ((hr = dxgiFactory->CreateSwapChain(commandQueue, &swapChainDesc, &swapChain)) < 0)
                                            _mEBreak_("Failed to create DXGI swap chain, Result: {}", hr);
                                        _mInitMethodsTable_(44 + 19 + 9 + 60 + 18);
                                        _mSetMethodsTable_(0, device, 44);
                                        _mSetMethodsTable_(44, commandQueue, 19);
                                        _mSetMethodsTable_(44 + 19, commandAllocator, 9);
                                        _mSetMethodsTable_(44 + 19 + 9, commandList, 60);
                                        _mSetMethodsTable_(44 + 19 + 9 + 60, swapChain, 18);
                                        swapChain->Release();
                                        _mSBreak_();
                                    } while (0);
                                } while (0);
                                commandAllocator->Release();
                            } while (0);
                            commandQueue->Release();
                        } while (0);
                        device->Release();
                    } while (0);
                    adapter->Release();
                } while (0);
                dxgiFactory->Release();
            }
            default:
            {
                _mEBreak_("Why are you here?", 0);
            }
            }
            ::DestroyWindow(TestWnd);
            ::UnregisterClass(TestWndClass.lpszClassName, TestWndClass.hInstance);
        }
        default:
        {
            _mEBreak_("RenderType {} not supported", (int)renderType);
        }
        }
        if (!bSuccess)
        {
            throw err;
        }
        g_renderType = renderType;
    }

#undef _mEBreak_
#undef _mSBreak_
#undef _mInitMethodsTable_
#undef _mSetMethodsTable_
}
END_IMGUI_INBOUND_NAMESPACE