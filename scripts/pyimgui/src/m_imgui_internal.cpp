#include "m_imgui_internal.h"

namespace mImguiInternal{
    static RenderType::Enum g_renderType = RenderType::None;
    static PVOID* g_methodsTable = NULL;
    static size_t g_methodsTableSize = 0;
    
    RenderType::Enum reloadRenderType()
    {
        HANDLE h;
        if ((h = ::GetModuleHandle(_T("d3d9.dll"))) != NULL)
        {
            dbgPrint("RenderType D3D9, handle: %x\n", h);
            g_renderType = RenderType::D3D9;
        }
        else if ((h = ::GetModuleHandle(_T("d3d10.dll"))) != NULL)
        {
            dbgPrint("RenderType D3D10, handle: %x\n", h);
            g_renderType = RenderType::D3D10;
        }
        else if ((h = ::GetModuleHandle(_T("d3d11.dll"))) != NULL)
        {
            dbgPrint("RenderType D3D11, handle: %x\n", h);
            g_renderType = RenderType::D3D11;
        }
        else if ((h = ::GetModuleHandle(_T("d3d12.dll"))) != NULL)
        {
            dbgPrint("RenderType D3D12, handle: %x\n", h);
            g_renderType = RenderType::D3D12;
        }
        else
        {
            dbgPrint("RenderType Unknown\n");
            g_renderType = RenderType::Unknown;
        }
        return g_renderType;
    }

    RenderType::Enum getRenderType()
    {
        if (g_renderType == RenderType::None || g_renderType == RenderType::Auto)
        {
            return reloadRenderType();
        }
        return g_renderType;
    }

    PVOID getMethod(size_t index)
    {
        if (g_methodsTable == NULL || index >= g_methodsTableSize)
        {
            return NULL;
        }
        return g_methodsTable[index];
    }
    # define _EBREAK_ {errline = __LINE__;break;}
    # define _SBREAK_ {errline = 0;break;}
    int32_t init(RenderType::Enum renderType)
    {
        /*if errline == 0, success*/
        /*if errline > 0, locale errline by source*/
        /*if errline < 0, unhandled error*/
        int32_t errline = -1;

        if (renderType == RenderType::None || renderType == RenderType::Auto)
        {
            renderType = reloadRenderType();
        }

        dbgPrint("RenderType: %d\n", renderType);

        switch (renderType)
        {
            case RenderType::D3D9:
            case RenderType::D3D10:
            case RenderType::D3D11:
            case RenderType::D3D12:
            {
                WNDCLASSEX TestWndClass; // a default window class to probe vt
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
                     NULL, NULL, TestWndClass.hInstance, NULL
                     );
                
                switch (renderType)
                {
                    case RenderType::D3D9:
                    {
                        HMODULE libD3D9;
                        if ((libD3D9 = ::GetModuleHandle(_T("d3d9.dll"))) == NULL) _EBREAK_;

                        void* Direct3DCreate9;
                        if ((Direct3DCreate9 = ::GetProcAddress(libD3D9, "Direct3DCreate9")) == NULL) _EBREAK_;

                        LPDIRECT3D9 direct3D9;
                        if ((direct3D9 = ((LPDIRECT3D9(WINAPI*)(UINT))(Direct3DCreate9))(D3D_SDK_VERSION)) == NULL) _EBREAK_;
                        
                        do{
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
                            if (direct3D9->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, TestWnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_DISABLE_DRIVER_MANAGEMENT, &d3dpp, &device) < 0)
                                _EBREAK_;
                             g_methodsTableSize = 119;
                            g_methodsTable = (PVOID*)malloc(g_methodsTableSize * sizeof(PVOID));
                            memcpy(g_methodsTable, *(PVOID**)device, g_methodsTableSize * sizeof(PVOID));
                            device->Release();
                        }while(0);
                        direct3D9->Release();
                        _SBREAK_;
                    }
                    case RenderType::D3D10:
                    {
                        HMODULE libDXGI,libD3D10;
                        if ((libDXGI = ::GetModuleHandle(_T("dxgi.dll"))) == NULL) _EBREAK_;
                        if ((libD3D10 = ::GetModuleHandle(_T("d3d10.dll"))) == NULL) _EBREAK_;

                        PVOID CreateDXGIFactory, mD3D10CreateDeviceAndSwapChain;
                        if ((CreateDXGIFactory = ::GetProcAddress(libDXGI, "CreateDXGIFactory")) == NULL)_EBREAK_;
                        if ((mD3D10CreateDeviceAndSwapChain = ::GetProcAddress(libD3D10, "D3D10CreateDeviceAndSwapChain")) == NULL) _EBREAK_;

                        IDXGIFactory* dxgiFactory;
                        if (((HRESULT(WINAPI*)(REFIID, void**))(CreateDXGIFactory))(IID_PPV_ARGS(&dxgiFactory)) < 0) _EBREAK_;

                        do{
                            IDXGIAdapter* adapter;
                            if (dxgiFactory->EnumAdapters(0, &adapter) < 0) _EBREAK_;
                            do{
                                DXGI_RATIONAL refreshRate = { 60, 1 };
                                DXGI_MODE_DESC bufferDesc = { 100, 100, refreshRate, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED };
                                DXGI_SAMPLE_DESC sampleDesc = { 1, 0 };
                                DXGI_SWAP_CHAIN_DESC swapChainDesc = { bufferDesc, sampleDesc, DXGI_USAGE_RENDER_TARGET_OUTPUT, 1, TestWnd, TRUE, DXGI_SWAP_EFFECT_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH };

                                IDXGISwapChain* swapChain;
                                ID3D10Device* device;
                                if ((
                                    (HRESULT(WINAPI*)(IDXGIAdapter*, D3D10_DRIVER_TYPE, HMODULE, UINT, UINT, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D10Device**))
                                    (mD3D10CreateDeviceAndSwapChain)
                                )(
                                    adapter, D3D10_DRIVER_TYPE_HARDWARE, NULL, 0, D3D10_SDK_VERSION, &swapChainDesc, &swapChain, &device
                                ) < 0) _EBREAK_;

                                g_methodsTableSize = 18+98;
                                g_methodsTable = (PVOID*)malloc(g_methodsTableSize * sizeof(PVOID));
                                memcpy(g_methodsTable, *(PVOID**)swapChain, 18 * sizeof(PVOID));
                                memcpy(g_methodsTable + 18, *(PVOID**)device, 98 * sizeof(PVOID));

                                swapChain->Release();
                                device->Release();
                                _SBREAK_;
                            }while(0);
                            adapter->Release();
                        }while(0);
                        dxgiFactory->Release();
                    }
                    case RenderType::D3D11:
                    {
                        HMODULE libD3D11;
                        if ((libD3D11 = ::GetModuleHandle(_T("d3d11.dll"))) == NULL) _EBREAK_;
                        PVOID D3D11CreateDeviceAndSwapChain;
                        if ((D3D11CreateDeviceAndSwapChain = ::GetProcAddress(libD3D11, "D3D11CreateDeviceAndSwapChain")) == NULL) _EBREAK_;
                        D3D_FEATURE_LEVEL featureLevel;
                        IDXGISwapChain* swapChain;
                        ID3D11Device* device;
                        ID3D11DeviceContext* context;
                        const D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0 };
                        DXGI_RATIONAL refreshRate = { 60, 1 };
                        DXGI_MODE_DESC bufferDesc = { 100, 100, refreshRate, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED };
                        DXGI_SAMPLE_DESC sampleDesc = { 1, 0 };
                        DXGI_SWAP_CHAIN_DESC swapChainDesc = { bufferDesc, sampleDesc, DXGI_USAGE_RENDER_TARGET_OUTPUT, 1, TestWnd, TRUE, DXGI_SWAP_EFFECT_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH };
                        if((
                            (HRESULT(WINAPI*)(_In_opt_ IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*, UINT, UINT, const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**))
                            (D3D11CreateDeviceAndSwapChain)
                        )(
                            NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, featureLevels, 2, D3D11_SDK_VERSION, &swapChainDesc, &swapChain, &device, &featureLevel, &context
                        ) < 0) _EBREAK_;
                        g_methodsTableSize = 18+43+144;
                        g_methodsTable = (PVOID*)malloc(g_methodsTableSize * sizeof(PVOID));
                        memcpy(g_methodsTable, *(PVOID**)swapChain, 18 * sizeof(PVOID));
                        memcpy(g_methodsTable + 18, *(PVOID**)device, 43 * sizeof(PVOID));
                        memcpy(g_methodsTable + 18 + 43, *(PVOID**)context, 144 * sizeof(PVOID));

                        swapChain->Release();
                        device->Release();
                        context->Release();
                        _SBREAK_;
                    }
                    case RenderType::D3D12:
                    {
                        HMODULE libDXGI,libD3D12;
                        if ((libDXGI = ::GetModuleHandle(_T("dxgi.dll"))) == NULL) _EBREAK_;
                        if ((libD3D12 = ::GetModuleHandle(_T("d3d12.dll"))) == NULL) _EBREAK_;
                        PVOID CreateDXGIFactory, D3D12CreateDevice;
                        if ((CreateDXGIFactory = ::GetProcAddress(libDXGI, "CreateDXGIFactory")) == NULL) _EBREAK_;
                        if ((D3D12CreateDevice = ::GetProcAddress(libD3D12, "D3D12CreateDevice")) == NULL) _EBREAK_;
                        IDXGIFactory* dxgiFactory;
                        if (((HRESULT(WINAPI*)(REFIID, void**))(CreateDXGIFactory))(IID_PPV_ARGS(&dxgiFactory)) < 0) _EBREAK_;
                        do{
                            IDXGIAdapter* adapter;
                            if (dxgiFactory->EnumAdapters(0, &adapter) < 0) _EBREAK_;
                            do{
                                ID3D12Device* device;
                                if ((
                                    (HRESULT(WINAPI*)(IUnknown*, D3D_FEATURE_LEVEL, REFIID, void**))
                                    (D3D12CreateDevice)
                                )(
                                    adapter, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), (void**)&device
                                ) < 0) _EBREAK_;
                                do{
                                    ID3D12CommandQueue* commandQueue;
                                    D3D12_COMMAND_QUEUE_DESC queueDesc = { D3D12_COMMAND_LIST_TYPE_DIRECT, 0, D3D12_COMMAND_QUEUE_FLAG_NONE, 0 };
                                    if (device->CreateCommandQueue(&queueDesc, __uuidof(ID3D12CommandQueue), (void**)&commandQueue) < 0) _EBREAK_;
                                    do{
                                        ID3D12CommandAllocator* commandAllocator;
                                        if (device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, __uuidof(ID3D12CommandAllocator), (void**)&commandAllocator) < 0) _EBREAK_;
                                        do{
                                            ID3D12GraphicsCommandList* commandList;
                                            if (device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, commandAllocator, NULL, __uuidof(ID3D12GraphicsCommandList), (void**)&commandList) < 0) _EBREAK_;
                                            do{
                                                DXGI_RATIONAL refreshRate = { 60, 1 };
                                                DXGI_MODE_DESC bufferDesc = { 100, 100, refreshRate, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED };
                                                DXGI_SAMPLE_DESC sampleDesc = { 1, 0 };
                                                DXGI_SWAP_CHAIN_DESC swapChainDesc = { bufferDesc, sampleDesc, DXGI_USAGE_RENDER_TARGET_OUTPUT, 2, TestWnd, TRUE, DXGI_SWAP_EFFECT_FLIP_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH };
                                                IDXGISwapChain* swapChain;
                                                if (dxgiFactory->CreateSwapChain(commandQueue, &swapChainDesc, &swapChain) < 0) _EBREAK_;
                                                g_methodsTableSize = 44 + 19 + 9 + 60 + 18;
                                                g_methodsTable = (PVOID*)malloc(g_methodsTableSize * sizeof(PVOID));
                                                memcpy(g_methodsTable, *(PVOID**)device, 44 * sizeof(PVOID));
                                                memcpy(g_methodsTable + 44, *(PVOID**)commandQueue, 19 * sizeof(PVOID));
                                                memcpy(g_methodsTable + 44 + 19, *(PVOID**)commandAllocator, 9 * sizeof(PVOID));
                                                memcpy(g_methodsTable + 44 + 19 + 9, *(PVOID**)commandList, 60 * sizeof(PVOID));
                                                memcpy(g_methodsTable + 44 + 19 + 9 + 60, *(PVOID**)swapChain, 18 * sizeof(PVOID));
                                                swapChain->Release();
                                                _SBREAK_;
                                            }while(0);
                                            commandAllocator->Release();
                                        }while(0);
                                        commandAllocator->Release();
                                    }while(0);
                                    commandQueue->Release();
                                }while(0);
                                device->Release();
                            }while(0);
                            adapter->Release();
                        }while(0);
                        dxgiFactory->Release();
                    }
                }
                ::DestroyWindow(TestWnd);
                ::UnregisterClass(TestWndClass.lpszClassName, TestWndClass.hInstance);
            }
        }
        if (errline != 0)
        {
            _throwV_("Error in internal imgui init: {}", errline);
        }
        return errline;
    }

}