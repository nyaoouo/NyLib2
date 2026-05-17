#include "./VkWindow.h"
#include "../common/ImguiInbound.h"
#include "../common/PyDetours.h"

#include <cstdlib>
#include <cstring>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

START_M_IMGUI_IMPL_VK_NAMESPACE
{
    namespace
    {
        void check_vk_result(VkResult err)
        {
            if (err == 0)
                return;
            if (err < 0)
                _throwV_("Vulkan call failed: VkResult={}", (int)err);
            dbgPrint("[vulkan] non-fatal VkResult = %d\n", (int)err);
        }

        bool IsInstanceExtensionAvailable(const std::vector<VkExtensionProperties> &properties, const char *extension)
        {
            for (const auto &p : properties)
                if (std::strcmp(p.extensionName, extension) == 0)
                    return true;
            return false;
        }

        int Hook_Platform_CreateVkSurface(ImGuiViewport* vp, ImU64 vk_inst, const void* vk_allocators, ImU64* out_vk_surface)
        {
            VkWin32SurfaceCreateInfoKHR info = {};
            info.sType = VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR;
            info.hinstance = ::GetModuleHandle(nullptr);
            info.hwnd = (HWND)vp->PlatformHandle;
            VkSurfaceKHR surface = VK_NULL_HANDLE;
            VkResult err = vkCreateWin32SurfaceKHR((VkInstance)vk_inst, &info, (const VkAllocationCallbacks*)vk_allocators, &surface);
            *out_vk_surface = (ImU64)surface;
            return (int)err;
        }
    }

    VkWindow::VkWindow(std::optional<py::function> renderCallback) : VkRender(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one VkWindow instance is allowed");
        _instance = this;
    }

    VkWindow::~VkWindow()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    void VkWindow::SetupVulkan(const std::vector<const char *> &requestedInstanceExtensions)
    {
        VkResult err;

        std::vector<const char *> instanceExtensions = requestedInstanceExtensions;

        // Enumerate available instance extensions.
        {
            uint32_t propCount = 0;
            vkEnumerateInstanceExtensionProperties(nullptr, &propCount, nullptr);
            std::vector<VkExtensionProperties> props(propCount);
            err = vkEnumerateInstanceExtensionProperties(nullptr, &propCount, props.data());
            check_vk_result(err);

            if (IsInstanceExtensionAvailable(props, VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_EXTENSION_NAME))
                instanceExtensions.push_back(VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_EXTENSION_NAME);
        }

        VkInstanceCreateInfo createInfo = {};
        createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        createInfo.enabledExtensionCount = (uint32_t)instanceExtensions.size();
        createInfo.ppEnabledExtensionNames = instanceExtensions.data();
        err = vkCreateInstance(&createInfo, this->allocator, &this->instance);
        check_vk_result(err);

        // Select physical device (prefer discrete GPU).
        {
            uint32_t gpuCount = 0;
            err = vkEnumeratePhysicalDevices(this->instance, &gpuCount, nullptr);
            check_vk_result(err);
            if (gpuCount == 0)
                _throw_("No Vulkan physical devices found");

            std::vector<VkPhysicalDevice> gpus(gpuCount);
            err = vkEnumeratePhysicalDevices(this->instance, &gpuCount, gpus.data());
            check_vk_result(err);

            this->physicalDevice = gpus[0];
            for (auto &dev : gpus)
            {
                VkPhysicalDeviceProperties props = {};
                vkGetPhysicalDeviceProperties(dev, &props);
                if (props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)
                {
                    this->physicalDevice = dev;
                    break;
                }
            }
        }

        // Select graphics queue family.
        {
            uint32_t count = 0;
            vkGetPhysicalDeviceQueueFamilyProperties(this->physicalDevice, &count, nullptr);
            std::vector<VkQueueFamilyProperties> queues(count);
            vkGetPhysicalDeviceQueueFamilyProperties(this->physicalDevice, &count, queues.data());
            for (uint32_t i = 0; i < count; i++)
                if (queues[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)
                {
                    this->queueFamily = i;
                    break;
                }
            if (this->queueFamily == (uint32_t)-1)
                _throw_("No graphics queue family found");
        }

        // Create logical device + queue.
        {
            std::vector<const char *> deviceExtensions = {"VK_KHR_swapchain"};
            float queuePriority[] = {1.0f};
            VkDeviceQueueCreateInfo queueInfo = {};
            queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
            queueInfo.queueFamilyIndex = this->queueFamily;
            queueInfo.queueCount = 1;
            queueInfo.pQueuePriorities = queuePriority;

            VkDeviceCreateInfo deviceInfo = {};
            deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
            deviceInfo.queueCreateInfoCount = 1;
            deviceInfo.pQueueCreateInfos = &queueInfo;
            deviceInfo.enabledExtensionCount = (uint32_t)deviceExtensions.size();
            deviceInfo.ppEnabledExtensionNames = deviceExtensions.data();
            err = vkCreateDevice(this->physicalDevice, &deviceInfo, this->allocator, &this->device);
            check_vk_result(err);
            vkGetDeviceQueue(this->device, this->queueFamily, 0, &this->queue);
        }

        // Create descriptor pool large enough for ImGui's combined image sampler set + headroom.
        {
            VkDescriptorPoolSize poolSizes[] = {
                {VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 16},
            };
            VkDescriptorPoolCreateInfo poolInfo = {};
            poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
            poolInfo.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
            poolInfo.maxSets = 16;
            poolInfo.poolSizeCount = (uint32_t)IM_ARRAYSIZE(poolSizes);
            poolInfo.pPoolSizes = poolSizes;
            err = vkCreateDescriptorPool(this->device, &poolInfo, this->allocator, &this->descriptorPool);
            check_vk_result(err);
        }
    }

    void VkWindow::SetupVulkanWindow(VkSurfaceKHR surface, int width, int height)
    {
        ImGui_ImplVulkanH_Window *wd = &this->mainWindowData;
        wd->Surface = surface;

        VkBool32 supported = VK_FALSE;
        vkGetPhysicalDeviceSurfaceSupportKHR(this->physicalDevice, this->queueFamily, wd->Surface, &supported);
        if (supported != VK_TRUE)
            _throw_("WSI not supported on selected queue family");

        const VkFormat requestSurfaceImageFormat[] = {VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_B8G8R8_UNORM, VK_FORMAT_R8G8B8_UNORM};
        const VkColorSpaceKHR requestSurfaceColorSpace = VK_COLORSPACE_SRGB_NONLINEAR_KHR;
        wd->SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(this->physicalDevice, wd->Surface, requestSurfaceImageFormat,
                                                                   (size_t)IM_ARRAYSIZE(requestSurfaceImageFormat), requestSurfaceColorSpace);

        VkPresentModeKHR presentModes[] = {VK_PRESENT_MODE_FIFO_KHR};
        wd->PresentMode = ImGui_ImplVulkanH_SelectPresentMode(this->physicalDevice, wd->Surface, presentModes, IM_ARRAYSIZE(presentModes));

        if (this->minImageCount < 2)
            this->minImageCount = 2;
        ImGui_ImplVulkanH_CreateOrResizeWindow(this->instance, this->physicalDevice, this->device, wd, this->queueFamily, this->allocator,
                                                width, height, this->minImageCount);
    }

    void VkWindow::CleanupVulkanWindow()
    {
        ImGui_ImplVulkanH_DestroyWindow(this->instance, this->device, &this->mainWindowData, this->allocator);
    }

    void VkWindow::CleanupVulkan()
    {
        if (this->descriptorPool)
        {
            vkDestroyDescriptorPool(this->device, this->descriptorPool, this->allocator);
            this->descriptorPool = VK_NULL_HANDLE;
        }
        if (this->device)
        {
            vkDestroyDevice(this->device, this->allocator);
            this->device = VK_NULL_HANDLE;
        }
        if (this->instance)
        {
            vkDestroyInstance(this->instance, this->allocator);
            this->instance = VK_NULL_HANDLE;
        }
    }

    void VkWindow::FrameRender(ImDrawData *drawData)
    {
        ImGui_ImplVulkanH_Window *wd = &this->mainWindowData;
        VkResult err;
        VkSemaphore imageAcquired = wd->FrameSemaphores[wd->SemaphoreIndex].ImageAcquiredSemaphore;
        VkSemaphore renderComplete = wd->FrameSemaphores[wd->SemaphoreIndex].RenderCompleteSemaphore;
        err = vkAcquireNextImageKHR(this->device, wd->Swapchain, UINT64_MAX, imageAcquired, VK_NULL_HANDLE, &wd->FrameIndex);
        if (err == VK_ERROR_OUT_OF_DATE_KHR || err == VK_SUBOPTIMAL_KHR)
        {
            this->swapChainRebuild = true;
            return;
        }
        check_vk_result(err);

        ImGui_ImplVulkanH_Frame *fd = &wd->Frames[wd->FrameIndex];
        err = vkWaitForFences(this->device, 1, &fd->Fence, VK_TRUE, UINT64_MAX);
        check_vk_result(err);
        err = vkResetFences(this->device, 1, &fd->Fence);
        check_vk_result(err);

        err = vkResetCommandPool(this->device, fd->CommandPool, 0);
        check_vk_result(err);

        VkCommandBufferBeginInfo cbBegin = {};
        cbBegin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        cbBegin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        err = vkBeginCommandBuffer(fd->CommandBuffer, &cbBegin);
        check_vk_result(err);

        VkRenderPassBeginInfo rpBegin = {};
        rpBegin.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
        rpBegin.renderPass = wd->RenderPass;
        rpBegin.framebuffer = fd->Framebuffer;
        rpBegin.renderArea.extent.width = (uint32_t)wd->Width;
        rpBegin.renderArea.extent.height = (uint32_t)wd->Height;
        rpBegin.clearValueCount = 1;
        rpBegin.pClearValues = &wd->ClearValue;
        vkCmdBeginRenderPass(fd->CommandBuffer, &rpBegin, VK_SUBPASS_CONTENTS_INLINE);

        ImGui_ImplVulkan_RenderDrawData(drawData, fd->CommandBuffer);

        vkCmdEndRenderPass(fd->CommandBuffer);

        VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        VkSubmitInfo submit = {};
        submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.waitSemaphoreCount = 1;
        submit.pWaitSemaphores = &imageAcquired;
        submit.pWaitDstStageMask = &waitStage;
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &fd->CommandBuffer;
        submit.signalSemaphoreCount = 1;
        submit.pSignalSemaphores = &renderComplete;
        err = vkEndCommandBuffer(fd->CommandBuffer);
        check_vk_result(err);
        err = vkQueueSubmit(this->queue, 1, &submit, fd->Fence);
        check_vk_result(err);
    }

    void VkWindow::FramePresent()
    {
        if (this->swapChainRebuild)
            return;
        ImGui_ImplVulkanH_Window *wd = &this->mainWindowData;
        VkSemaphore renderComplete = wd->FrameSemaphores[wd->SemaphoreIndex].RenderCompleteSemaphore;
        VkPresentInfoKHR info = {};
        info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
        info.waitSemaphoreCount = 1;
        info.pWaitSemaphores = &renderComplete;
        info.swapchainCount = 1;
        info.pSwapchains = &wd->Swapchain;
        info.pImageIndices = &wd->FrameIndex;
        VkResult err = vkQueuePresentKHR(this->queue, &info);
        if (err == VK_ERROR_OUT_OF_DATE_KHR || err == VK_SUBOPTIMAL_KHR)
        {
            this->swapChainRebuild = true;
            return;
        }
        check_vk_result(err);
        wd->SemaphoreIndex = (wd->SemaphoreIndex + 1) % wd->SemaphoreCount;
    }

    LRESULT WINAPI VkImguiWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        LRESULT trayResult = 0;
        if (M_IMGUI_IMPL_NAMESPACE::RenderBase::ProcessTrayWindowProc(hWnd, msg, wParam, lParam, trayResult))
            return trayResult;
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;
        if (VkWindow::_instance == nullptr)
            return ::DefWindowProc(hWnd, msg, wParam, lParam);
        switch (msg)
        {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED)
            {
                VkWindow::_instance->pendingWidth = (int)LOWORD(lParam);
                VkWindow::_instance->pendingHeight = (int)HIWORD(lParam);
                VkWindow::_instance->swapChainRebuild = true;
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
        }
        return ::DefWindowProc(hWnd, msg, wParam, lParam);
    }

    void VkWindow::Serve()
    {
        WNDCLASSEX wc = {sizeof(wc), CS_CLASSDC, VkImguiWndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("mImguiWindowVk"), nullptr};
        ::RegisterClassEx(&wc);
        HWND hwnd = ::CreateWindow(wc.lpszClassName, _T(""), WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);
        if (hwnd == nullptr)
            _throwV_("Failed to create window, error code: {}", GetLastError());
        this->SetHwnd(hwnd);

        try
        {
            std::vector<const char *> extensions = {VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_WIN32_SURFACE_EXTENSION_NAME};
            this->SetupVulkan(extensions);

            VkWin32SurfaceCreateInfoKHR surfaceInfo = {};
            surfaceInfo.sType = VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR;
            surfaceInfo.hinstance = wc.hInstance;
            surfaceInfo.hwnd = hwnd;
            VkSurfaceKHR surface = VK_NULL_HANDLE;
            VkResult err = vkCreateWin32SurfaceKHR(this->instance, &surfaceInfo, this->allocator, &surface);
            check_vk_result(err);

            RECT clientRect = {};
            ::GetClientRect(hwnd, &clientRect);
            int width = clientRect.right - clientRect.left;
            int height = clientRect.bottom - clientRect.top;
            if (width <= 0)
                width = 1280;
            if (height <= 0)
                height = 800;
            this->SetupVulkanWindow(surface, width, height);
        }
        catch (...)
        {
            this->CleanupVulkanWindow();
            this->CleanupVulkan();
            ::DestroyWindow(hwnd);
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            throw;
        }

        ::ShowWindow(this->hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(this->hwnd);
        ::SetWindowTextA(this->hwnd, this->title.c_str());

        this->ctx = ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
        ImGui::StyleColorsLight();
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGuiStyle &style = ImGui::GetStyle();
            style.WindowRounding = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
        }

        ImGui_ImplWin32_Init(this->hwnd);
        ImGui::GetPlatformIO().Platform_CreateVkSurface = Hook_Platform_CreateVkSurface;

        ImGui_ImplVulkan_InitInfo initInfo = {};
        initInfo.Instance = this->instance;
        initInfo.PhysicalDevice = this->physicalDevice;
        initInfo.Device = this->device;
        initInfo.QueueFamily = this->queueFamily;
        initInfo.Queue = this->queue;
        initInfo.PipelineCache = this->pipelineCache;
        initInfo.DescriptorPool = this->descriptorPool;
        initInfo.RenderPass = this->mainWindowData.RenderPass;
        initInfo.Subpass = 0;
        initInfo.MinImageCount = this->minImageCount;
        initInfo.ImageCount = this->mainWindowData.ImageCount;
        initInfo.MSAASamples = VK_SAMPLE_COUNT_1_BIT;
        initInfo.Allocator = this->allocator;
        initInfo.CheckVkResultFn = check_vk_result;
        ImGui_ImplVulkan_Init(&initInfo);

        do
        {
            MSG msg;
            bool done = false;
            while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
            {
                ::TranslateMessage(&msg);
                ::DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    done = true;
            }
            if (done)
                break;

            if (this->swapChainRebuild && this->pendingWidth > 0 && this->pendingHeight > 0)
            {
                ImGui_ImplVulkan_SetMinImageCount(this->minImageCount);
                ImGui_ImplVulkanH_CreateOrResizeWindow(this->instance, this->physicalDevice, this->device, &this->mainWindowData,
                                                       this->queueFamily, this->allocator, this->pendingWidth, this->pendingHeight,
                                                       this->minImageCount);
                this->mainWindowData.FrameIndex = 0;
                this->swapChainRebuild = false;
            }
            if (::IsIconic(this->hwnd))
            {
                ::Sleep(10);
                continue;
            }

            this->ProcessCallBeforeFrameOnce(py::cast(this));

            ImGui_ImplVulkan_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            this->ProcessRenderCallback(py::cast(this));
            ImGui::Render();
            ImDrawData *drawData = ImGui::GetDrawData();
            const bool minimized = (drawData->DisplaySize.x <= 0.0f || drawData->DisplaySize.y <= 0.0f);

            this->mainWindowData.ClearValue.color.float32[0] = this->ClearColor.x * this->ClearColor.w;
            this->mainWindowData.ClearValue.color.float32[1] = this->ClearColor.y * this->ClearColor.w;
            this->mainWindowData.ClearValue.color.float32[2] = this->ClearColor.z * this->ClearColor.w;
            this->mainWindowData.ClearValue.color.float32[3] = this->ClearColor.w;
            if (!minimized)
                this->FrameRender(drawData);

            if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
            {
                ImGui::UpdatePlatformWindows();
                ImGui::RenderPlatformWindowsDefault();
            }

            if (!minimized)
                this->FramePresent();
        } while (true);

        vkDeviceWaitIdle(this->device);
        ImGui_ImplVulkan_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(this->ctx);
        this->ctx = nullptr;
        this->CleanupVulkanWindow();
        this->CleanupVulkan();
        ::DestroyWindow(this->hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        this->hwnd = nullptr;
    }

    // -----------------------------------------------------------------------------
    // VkInbound: stub. See plan + class doc for the reasoning.
    // Working host-process Vulkan inbound requires layered interception of
    //   vkCreateInstance / vkCreateDevice / vkCreateSwapchainKHR
    // and cooperative reuse of the host's queue, render pass, descriptor pool,
    // and command buffers. That is outside this delivery.
    // -----------------------------------------------------------------------------
    VkInbound::VkInbound(std::optional<py::function> renderCallback) : VkRender(renderCallback)
    {
        if (_instance != nullptr)
            _throw_("Only one VkInbound instance is allowed");
        _instance = this;
    }

    VkInbound::~VkInbound()
    {
        if (_instance == this)
            _instance = nullptr;
    }

    void VkInbound::Attach()
    {
        _throw_("VkInbound is not yet implemented: hooking vkQueuePresentKHR requires cooperative interception of host vkCreateInstance/vkCreateDevice/vkCreateSwapchainKHR state. Use VkWindow for now.");
    }

    void VkInbound::Detach()
    {
        // Nothing to detach; Attach() always throws.
    }

    void pybind_setup_mImguiImpl_Vk(pybind11::module_ m)
    {
        pybind_setup_mImguiImpl_RenderBase(m);
        py::class_<VkRender, RenderBase>(m, "_VkRender", py::dynamic_attr(), py::module_local())
            .def_static("InvalidateDeviceObjects", []() { ImGui_ImplVulkan_CreateFontsTexture(); })
            .def_static("CreateFontsTexture", []() { return ImGui_ImplVulkan_CreateFontsTexture(); })
            .def_static("DestroyFontsTexture", []() { ImGui_ImplVulkan_DestroyFontsTexture(); })
            .def_static("SetMinImageCount", [](uint32_t count) { ImGui_ImplVulkan_SetMinImageCount(count); }, py::arg("count"));
        py::class_<VkWindow, VkRender>(m, "VkWindow", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def_readwrite("ClearColor", &VkWindow::ClearColor)
            .def("Serve", &VkWindow::Serve, py::call_guard<py::gil_scoped_release>());
        py::class_<VkInbound, VkRender>(m, "VkInbound", py::dynamic_attr(), py::module_local())
            .def(py::init<std::optional<py::function>>(), py::arg("renderCallback") = py::none())
            .def("Attach", &VkInbound::Attach)
            .def("Detach", &VkInbound::Detach);
    }
}
END_M_IMGUI_IMPL_VK_NAMESPACE
