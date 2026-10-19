#pragma once
#include "./gHeader.h"
#include "./OverlayTypes.h"
#include <array>
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

    // Raises ValueError if transform holds a TextureTransform value pybind11 did not reject; nullopt is valid.
    // Call this with the GIL held, before releasing it to decode/transform off-thread.
    inline void CheckTextureTransform(std::optional<OVERLAY_TYPES_NAMESPACE::TextureTransform> transform)
    {
        if (transform.has_value() && *transform != OVERLAY_TYPES_NAMESPACE::TextureTransform::GrayscaleBT709)
            throw py::value_error(std::format("unknown TextureTransform value: {}", (int)*transform));
    }

    // Raises ValueError if format holds a TextureFormat value pybind11 did not reject.
    inline void CheckTextureFormat(OVERLAY_TYPES_NAMESPACE::TextureFormat format)
    {
        using OVERLAY_TYPES_NAMESPACE::TextureFormat;
        if (format != TextureFormat::RGBA8 && format != TextureFormat::BGRA8)
            throw py::value_error(std::format("unknown TextureFormat value: {}", (int)format));
    }

    // Raises ValueError if blend holds a TextureBlend value pybind11 did not reject.
    inline void CheckTextureBlend(OVERLAY_TYPES_NAMESPACE::TextureBlend blend)
    {
        using OVERLAY_TYPES_NAMESPACE::TextureBlend;
        if (blend != TextureBlend::Straight && blend != TextureBlend::Premultiplied)
            throw py::value_error(std::format("unknown TextureBlend value: {}", (int)blend));
    }

    // Returns rect (x, y, w, h) if it lies inside width x height and the texture was created with mips=False, else raises ValueError.
    inline std::array<int, 4> CheckTextureRect(const std::array<int, 4> &rect, int width, int height, bool mips)
    {
        if (mips)
            throw py::value_error("rect updates need a texture created with mips=False");
        int x = rect[0], y = rect[1], w = rect[2], h = rect[3];
        if (x < 0 || y < 0 || w < 1 || h < 1 || w > width - x || h > height - y)
            throw py::value_error(std::format("rect must satisfy 0 <= x, 0 <= y, 1 <= w, 1 <= h, x + w <= width and y + h <= height, got ({}, {}, {}, {}) for {}x{}", x, y, w, h, width, height));
        return rect;
    }

    // Converts tight RGBA8 rows in place: GrayscaleBT709 sets R = G = B = BT.709 luma, alpha unchanged; nullopt does nothing.
    // Needs no GIL; never pass a caller's Python buffer. Call CheckTextureTransform first; this does not validate.
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
