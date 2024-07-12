#include "./Helper_Cmn.h"
#include <d3d12.h>
#include <dxgi1_4.h>

#define M_IMGUI_HELPER_Dx12_NAMESPACE M_IMGUI_HELPER_NAMESPACE::Helper_Dx12
#define START_M_IMGUI_HELPER_Dx12_NAMESPACE \
    START_M_IMGUI_HELPER_NAMESPACE          \
    {                                       \
        namespace Helper_Dx12
#define END_M_IMGUI_HELPER_Dx12_NAMESPACE \
    }                                     \
    END_M_IMGUI_HELPER_NAMESPACE

START_M_IMGUI_HELPER_Dx12_NAMESPACE
{
    class Dx12TextureHelper
    {
    public:
        ID3D12Device *d3d_device;
        D3D12_CPU_DESCRIPTOR_HANDLE srv_cpu_handle;
        D3D12_GPU_DESCRIPTOR_HANDLE srv_gpu_handle;
        ID3D12Resource *srv = nullptr;
        int width = 0;
        int height = 0;

        Dx12TextureHelper(
            ID3D12Device *d3dDevice,
            D3D12_CPU_DESCRIPTOR_HANDLE srv_cpu_handle,
            D3D12_GPU_DESCRIPTOR_HANDLE srv_gpu_handle,
            const char *filename = NULL) : d3d_device(d3dDevice), srv_cpu_handle(srv_cpu_handle), srv_gpu_handle(srv_gpu_handle)
        {
            if (filename != nullptr)
                LoadTextureFromFile(filename);
        }

        ~Dx12TextureHelper()
        {
            FreeTexture();
        }

        inline void FreeTexture()
        {
            if (srv != nullptr)
            {
                srv->Release();
                srv = nullptr;
            }
            width = height = 0;
        }
        void LoadTextureFromFile(const char *filename);
    };

    inline void pybind_setup_helper_Dx12(pybind11::module_ m)
    {
        py::class_<Dx12TextureHelper>(m, "Dx12TextureHelper", py::dynamic_attr())
            .def("LoadTextureFromFile", &Dx12TextureHelper::LoadTextureFromFile)
            .def("__bool__", [](const Dx12TextureHelper &self)
                 { return self.srv != nullptr; })
            .def_property_readonly("handle", [](const Dx12TextureHelper &self)
                                   { return (size_t)self.srv_gpu_handle.ptr; })
            .def_property_readonly("width", [](const Dx12TextureHelper &self)
                                   { return self.width; })
            .def_property_readonly("height", [](const Dx12TextureHelper &self)
                                   { return self.height; })
            .def_property_readonly("size", [](const Dx12TextureHelper &self)
                                   { ImVec2 size = { (float)self.width, (float)self.height }; return size; }, py::return_value_policy::move);
    };
}
END_M_IMGUI_HELPER_Dx12_NAMESPACE