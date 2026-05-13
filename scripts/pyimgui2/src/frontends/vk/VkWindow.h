#pragma once

#include "../common/RenderBase.h"
#include "../common/Win32Hook.h"

#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include "imgui_impl_win32.h"
#include "imgui_impl_vulkan.h"

#define M_IMGUI_IMPL_VK_NAMESPACE M_IMGUI_IMPL_NAMESPACE::Impl_Vk
#define START_M_IMGUI_IMPL_VK_NAMESPACE START_M_IMGUI_IMPL_NAMESPACE { namespace Impl_Vk
#define END_M_IMGUI_IMPL_VK_NAMESPACE } END_M_IMGUI_IMPL_NAMESPACE

START_M_IMGUI_IMPL_VK_NAMESPACE
{
    class VkRender : public RenderBase
    {
    public:
        VkAllocationCallbacks *allocator = nullptr;
        VkInstance instance = VK_NULL_HANDLE;
        VkPhysicalDevice physicalDevice = VK_NULL_HANDLE;
        VkDevice device = VK_NULL_HANDLE;
        uint32_t queueFamily = (uint32_t)-1;
        VkQueue queue = VK_NULL_HANDLE;
        VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
        VkPipelineCache pipelineCache = VK_NULL_HANDLE;

        VkRender(std::optional<py::function> renderCallback = std::nullopt) : RenderBase(renderCallback) {}
    };

    class VkWindow : public VkRender
    {
    public:
        static inline VkWindow *_instance = nullptr;
        ImVec4 ClearColor = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

        ImGui_ImplVulkanH_Window mainWindowData = {};
        uint32_t minImageCount = 2;
        bool swapChainRebuild = false;
        int pendingWidth = 0;
        int pendingHeight = 0;

        VkWindow(std::optional<py::function> renderCallback = std::nullopt);
        ~VkWindow();

        void SetupVulkan(const std::vector<const char *> &instanceExtensions);
        void SetupVulkanWindow(VkSurfaceKHR surface, int width, int height);
        void CleanupVulkanWindow();
        void CleanupVulkan();
        void FrameRender(ImDrawData *drawData);
        void FramePresent();
        void Serve();
    };

    class VkInbound : public VkRender
    {
    public:
        static inline VkInbound *_instance = nullptr;

        VkInbound(std::optional<py::function> renderCallback = std::nullopt);
        ~VkInbound();

        void Attach();
        void Detach();
    };

    void pybind_setup_mImguiImpl_Vk(pybind11::module_ m);
}
END_M_IMGUI_IMPL_VK_NAMESPACE
