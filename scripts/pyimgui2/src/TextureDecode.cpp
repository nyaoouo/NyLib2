#define STBI_WINDOWS_UTF8
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include "./TextureDecode.h"
#include "./TextureData.h"

START_TEXTURE_DECODE_NAMESPACE
{
    // Decoded RGBA8 pixels: straight alpha, row 0 at the top, tight rows of width*4 bytes.
    struct DecodedImage
    {
        int width = 0;
        int height = 0;
        py::bytes pixels;
    };

    // Decodes an image file on any thread; holds the GIL only to read the arguments and create the result.
    static DecodedImage DecodeImageImpl(const std::string &filename, std::optional<OVERLAY_TYPES_NAMESPACE::TextureTransform> transform)
    {
        TEXTURE_DATA_NAMESPACE::DecodedPixels image;
        {
            py::gil_scoped_release release;
            image = TEXTURE_DATA_NAMESPACE::DecodeFile(filename);
            TEXTURE_DATA_NAMESPACE::ApplyTransform(image.data.get(), image.width, image.height, transform);
        }
        size_t size = (size_t)image.width * (size_t)image.height * 4;
        PyObject *bytes = PyBytes_FromStringAndSize(nullptr, (Py_ssize_t)size);
        if (bytes == nullptr)
            throw py::error_already_set();
        DecodedImage result;
        result.width = image.width;
        result.height = image.height;
        result.pixels = py::reinterpret_steal<py::bytes>(bytes);
        char *dst = PyBytes_AS_STRING(bytes);
        {
            py::gil_scoped_release release;
            std::memcpy(dst, image.data.get(), size);
            image.data.reset();
        }
        return result;
    }

    void pybind_setup_TextureDecode(py::module_ m)
    {
        py::class_<DecodedImage>(m, "DecodedImage")
            .def_property_readonly("width", [](const DecodedImage &self) { return self.width; })
            .def_property_readonly("height", [](const DecodedImage &self) { return self.height; })
            .def_property_readonly("pixels", [](const DecodedImage &self) { return self.pixels; });

        m.def("DecodeImage", &DecodeImageImpl, py::arg("filename"), py::kw_only(), py::arg("transform") = py::none());
    }
}
END_TEXTURE_DECODE_NAMESPACE
