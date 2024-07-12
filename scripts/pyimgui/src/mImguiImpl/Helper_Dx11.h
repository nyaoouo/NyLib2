#include "./Helper_Cmn.h"
#include <d3d11.h>

#define M_IMGUI_HELPER_Dx11_NAMESPACE M_IMGUI_HELPER_NAMESPACE::Helper_Dx11
#define START_M_IMGUI_HELPER_Dx11_NAMESPACE \
    START_M_IMGUI_HELPER_NAMESPACE          \
    {                                       \
        namespace Helper_Dx11
#define END_M_IMGUI_HELPER_Dx11_NAMESPACE \
    }                                     \
    END_M_IMGUI_HELPER_NAMESPACE

START_M_IMGUI_HELPER_Dx11_NAMESPACE
{
    class Dx11TextureHelper
    {
    public:
        ID3D11Device *pd3dDevice;
        ID3D11ShaderResourceView *srv = nullptr;
        int width = 0;
        int height = 0;

        Dx11TextureHelper(ID3D11Device *pd3dDevice) : pd3dDevice(pd3dDevice) {}
        Dx11TextureHelper(ID3D11Device *pd3dDevice, const char *filename) : pd3dDevice(pd3dDevice)
        {
            if (filename != nullptr)
                LoadTextureFromFile(filename);
        }

        ~Dx11TextureHelper()
        {
            FreeTexture();
        }

        inline void FreeTexture() {
            if (srv != nullptr) {
                srv->Release();
                srv = nullptr;
            }
            width = height = 0;
        }
        void LoadTextureFromFile(const char *filename);
    };

    inline void pybind_setup_helper_Dx11(pybind11::module_ m) {
        py::class_<Dx11TextureHelper>(m, "Dx11TextureHelper", py::dynamic_attr())
            .def("LoadTextureFromFile", &Dx11TextureHelper::LoadTextureFromFile)
            .def("__bool__", [](const Dx11TextureHelper &self) { return self.srv != nullptr; })
            .def_property_readonly("handle", [](const Dx11TextureHelper &self) { return (size_t)self.srv; })
            .def_property_readonly("width", [](const Dx11TextureHelper &self) { return self.width; })
            .def_property_readonly("height", [](const Dx11TextureHelper &self) { return self.height; })
            .def_property_readonly("size", [](const Dx11TextureHelper &self) { ImVec2 size = { (float)self.width, (float)self.height }; return size; }, py::return_value_policy::move);
    };
}
END_M_IMGUI_HELPER_Dx11_NAMESPACE