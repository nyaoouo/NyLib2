#pragma once
#include "./gHeader.h"
#include "./OverlayTypes.h"
#ifndef STBI_INCLUDE_STB_IMAGE_H
#include "stb_image.h"
#endif

#define TEXTURE_DATA_NAMESPACE mNameSpace::TextureData
#define START_TEXTURE_DATA_NAMESPACE \
    namespace mNameSpace             \
    {                                \
        namespace TextureData
#define END_TEXTURE_DATA_NAMESPACE }

START_TEXTURE_DATA_NAMESPACE
{
    // Raises ValueError unless 1 <= width, height <= 16384.
    inline void CheckTextureSize(int width, int height)
    {
        if (width < 1 || width > 16384 || height < 1 || height > 16384)
            throw py::value_error(std::format("width and height must be in [1, 16384], got {}x{}", width, height));
    }

    // Pins the RGBA8 rows of a C-contiguous buffer for one call; every check runs before a pixel byte is read.
    // Construct and destroy with the GIL held. rowPitch 0 means width*4.
    class PixelView
    {
    public:
        PixelView(py::handle pixels, int width, int height, long long rowPitch)
        {
            if (PyObject_GetBuffer(pixels.ptr(), &this->view, PyBUF_STRIDES) != 0)
                throw py::error_already_set();
            try
            {
                this->Check(width, height, rowPitch);
            }
            catch (...)
            {
                PyBuffer_Release(&this->view);
                throw;
            }
        }

        ~PixelView()
        {
            PyBuffer_Release(&this->view);
        }

        PixelView(const PixelView &) = delete;
        PixelView &operator=(const PixelView &) = delete;

        const unsigned char *Bytes() const { return (const unsigned char *)this->view.buf; }
        UINT Pitch() const { return this->pitch; }

    private:
        Py_buffer view = {};
        UINT pitch = 0;

        void Check(int width, int height, long long rowPitch)
        {
            if (!PyBuffer_IsContiguous(&this->view, 'C'))
                throw py::value_error("pixels must be C-contiguous");
            long long tight = (long long)width * 4;
            if (rowPitch != 0 && (rowPitch < tight || rowPitch > 2147483647LL))
                throw py::value_error(std::format("rowPitch must be 0 or in [width*4 = {}, 2147483647], got {}", tight, rowPitch));
            this->pitch = (UINT)(rowPitch != 0 ? rowPitch : tight);
            long long length = (long long)this->view.len;
            if (rowPitch == 0 && length != tight * height)
                throw py::value_error(std::format("pixels must hold exactly width*height*4 = {} bytes, got {}", tight * height, length));
            if (rowPitch != 0 && length < rowPitch * height)
                throw py::value_error(std::format("pixels must hold at least rowPitch*height = {} bytes, got {}", rowPitch * height, length));
        }
    };

    // The tight RGBA8 rows that stbi_load(..., 4) returned.
    struct DecodedPixels
    {
        std::unique_ptr<unsigned char, void (*)(void *)> data{nullptr, stbi_image_free};
        int width = 0;
        int height = 0;
    };

    // Decodes an image file to RGBA8; RuntimeError on failure. Needs no GIL.
    inline DecodedPixels DecodeFile(const std::string &path)
    {
        DecodedPixels image;
        image.data.reset(stbi_load(path.c_str(), &image.width, &image.height, nullptr, 4));
        if (image.data == nullptr)
        {
            const char *reason = stbi_failure_reason();
            _throwV_("Failed to load image: {} ({})", path, reason != nullptr ? reason : "unknown reason");
        }
        return image;
    }

    // Converts tight RGBA8 rows in place: GrayscaleBT709 sets R = G = B = BT.709 luma, alpha unchanged; nullopt does nothing.
    // Needs no GIL; never pass a caller's Python buffer.
    inline void ApplyTransform(unsigned char *rgba, int width, int height, std::optional<OVERLAY_TYPES_NAMESPACE::TextureTransform> transform)
    {
        if (!transform.has_value() || *transform != OVERLAY_TYPES_NAMESPACE::TextureTransform::GrayscaleBT709)
            return;
        size_t count = (size_t)width * (size_t)height;
        for (size_t i = 0; i < count; i++, rgba += 4)
        {
            uint32_t y = (2126u * rgba[0] + 7152u * rgba[1] + 722u * rgba[2] + 5000u) / 10000u;
            rgba[0] = rgba[1] = rgba[2] = (unsigned char)y;
        }
    }
}
END_TEXTURE_DATA_NAMESPACE
