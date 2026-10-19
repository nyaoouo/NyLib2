#include "./OverlayTypes.h"

START_OVERLAY_TYPES_NAMESPACE
{
    void pybind_setup_OverlayTypes(py::module_ m)
    {
        // No py::arithmetic(): the frozen rule is int -> TypeError.
        py::enum_<InputPolicy>(m, "InputPolicy")
            .value("Auto", InputPolicy::Auto)
            .value("CaptureAll", InputPolicy::CaptureAll)
            .value("PassAll", InputPolicy::PassAll);

        py::enum_<HookMode>(m, "HookMode")
            .value("Detours", HookMode::Detours)
            .value("Vtable", HookMode::Vtable)
            .value("Auto", HookMode::Auto);

        py::enum_<OverlayZOrder>(m, "OverlayZOrder")
            .value("AboveTarget", OverlayZOrder::AboveTarget)
            .value("Topmost", OverlayZOrder::Topmost);

        py::enum_<GamepadPolicy>(m, "GamepadPolicy")
            .value("WhenForeground", GamepadPolicy::WhenForeground)
            .value("Always", GamepadPolicy::Always)
            .value("Never", GamepadPolicy::Never);

        py::enum_<TextureTransform>(m, "TextureTransform")
            .value("GrayscaleBT709", TextureTransform::GrayscaleBT709);

        py::enum_<TextureFilter>(m, "TextureFilter")
            .value("Point", TextureFilter::Point)
            .value("Linear", TextureFilter::Linear)
            .value("Anisotropic", TextureFilter::Anisotropic);

        py::enum_<TextureFormat>(m, "TextureFormat")
            .value("RGBA8", TextureFormat::RGBA8)
            .value("BGRA8", TextureFormat::BGRA8);

        py::enum_<TextureBlend>(m, "TextureBlend")
            .value("Straight", TextureBlend::Straight)
            .value("Premultiplied", TextureBlend::Premultiplied);
    }
}
END_OVERLAY_TYPES_NAMESPACE
