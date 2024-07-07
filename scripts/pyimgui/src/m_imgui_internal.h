#pragma once
#include "./gheader.h"
#include <dxgi.h>
#include <d3d9.h>
#include <d3d10_1.h>
#include <d3d10.h>
#include <d3d11.h>
#include <d3d12.h>

namespace mImguiInternal{
	struct RenderType
	{
		enum Enum
		{
			None,

			D3D9,
			D3D10,
			D3D11,
			D3D12,

			// OpenGL,
			// Vulkan,

			Auto,
			Unknown,
		};
	};

    int32_t init(RenderType::Enum renderType);
	RenderType::Enum reloadRenderType();
	RenderType::Enum getRenderType();
	PVOID getMethod(size_t index);
}