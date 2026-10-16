#pragma once
#include "./gHeader.h"

#define TEXTURE_DECODE_NAMESPACE mNameSpace::TextureDecode
#define START_TEXTURE_DECODE_NAMESPACE \
    namespace mNameSpace               \
    {                                  \
        namespace TextureDecode
#define END_TEXTURE_DECODE_NAMESPACE }

START_TEXTURE_DECODE_NAMESPACE
{
    // Register DecodedImage and DecodeImage on `m` (the top-level pyimgui module).
    // Must be called exactly once (DllMain.cpp, core only).
    void pybind_setup_TextureDecode(py::module_ m);
}
END_TEXTURE_DECODE_NAMESPACE
