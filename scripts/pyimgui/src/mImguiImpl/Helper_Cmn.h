#pragma once
#include "../gHeader.h"
#define STB_IMAGE_STATIC
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define M_IMGUI_HELPER_NAMESPACE mNameSpace::MImguiHelper
#define START_M_IMGUI_HELPER_NAMESPACE \
    namespace mNameSpace               \
    {                                  \
        namespace MImguiHelper
#define END_M_IMGUI_HELPER_NAMESPACE }