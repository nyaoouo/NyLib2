#include "./Helper_Dx11.h"

START_M_IMGUI_HELPER_Dx11_NAMESPACE
{
    void Dx11TextureHelper::LoadTextureFromFile(const char *filename)
    {
        // Load from disk into a raw RGBA buffer
        int image_width = 0;
        int image_height = 0;
        unsigned char *image_data = stbi_load(filename, &image_width, &image_height, NULL, 4);
        if (image_data == NULL) _throwV_("Failed to load image file {}", filename);

        this->FreeTexture();

        // Create texture
        D3D11_TEXTURE2D_DESC desc;
        ZeroMemory(&desc, sizeof(desc));
        desc.Width = image_width;
        desc.Height = image_height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        desc.CPUAccessFlags = 0;

        ID3D11Texture2D *pTexture = NULL;
        D3D11_SUBRESOURCE_DATA subResource;
        subResource.pSysMem = image_data;
        subResource.SysMemPitch = desc.Width * 4;
        subResource.SysMemSlicePitch = 0;
        this->pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);

        // Create texture view
        D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc;
        ZeroMemory(&srvDesc, sizeof(srvDesc));
        srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        srvDesc.Texture2D.MipLevels = desc.MipLevels;
        srvDesc.Texture2D.MostDetailedMip = 0;
        this->pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &this->srv);
        pTexture->Release();

        this->width = image_width;
        this->height = image_height;
        stbi_image_free(image_data);
    }
}
END_M_IMGUI_HELPER_Dx11_NAMESPACE