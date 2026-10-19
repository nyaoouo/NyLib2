#pragma once
#include "../../gHeader.h"

#define TEXTURE_MIPS_NAMESPACE mNameSpace::TextureMips
#define START_TEXTURE_MIPS_NAMESPACE \
    namespace mNameSpace             \
    {                                \
        namespace TextureMips
#define END_TEXTURE_MIPS_NAMESPACE }

START_TEXTURE_MIPS_NAMESPACE
{
    // Levels of a full mip chain: floor(log2(max(width, height))) + 1.
    inline int MipLevelCount(int width, int height)
    {
        int levels = 1;
        for (int size = width > height ? width : height; size > 1; size >>= 1)
            levels++;
        return levels;
    }

    // Levels 1..n-1 of an RGBA8 image, packed tightly level after level; entry k describes level k + 1.
    struct MipChain
    {
        std::vector<unsigned char> bytes;
        std::vector<size_t> offsets;
        std::vector<int> widths, heights;
    };

    // One 2x2 box-filter step, clamped duplicates count as samples; alpha-weighted colour, or a plain average with premultiplied.
    inline void DownsampleLevel(const unsigned char *src, int srcWidth, int srcHeight, size_t srcPitch, unsigned char *dst, int dstWidth, int dstHeight, bool premultiplied = false)
    {
        for (int y = 0; y < dstHeight; y++)
        {
            const unsigned char *rows[2];
            for (int j = 0; j < 2; j++)
                rows[j] = src + (size_t)(2 * y + j < srcHeight - 1 ? 2 * y + j : srcHeight - 1) * srcPitch;
            for (int x = 0; x < dstWidth; x++, dst += 4)
            {
                uint32_t sumA = 0, sumC[3] = {}, sumCA[3] = {};
                for (int j = 0; j < 2; j++)
                {
                    for (int i = 0; i < 2; i++)
                    {
                        const unsigned char *p = rows[j] + (size_t)(2 * x + i < srcWidth - 1 ? 2 * x + i : srcWidth - 1) * 4;
                        sumA += p[3];
                        for (int c = 0; c < 3; c++)
                        {
                            sumC[c] += p[c];
                            sumCA[c] += (uint32_t)p[c] * p[3];
                        }
                    }
                }
                for (int c = 0; c < 3; c++)
                    dst[c] = (unsigned char)(!premultiplied && sumA > 0 ? (sumCA[c] + sumA / 2) / sumA : (sumC[c] + 2) / 4);
                dst[3] = (unsigned char)((sumA + 2) / 4);
            }
        }
    }

    // Levels 1..n-1 of rgba (level 0, rows rowPitch bytes apart). Needs no GIL.
    inline MipChain BuildMipChain(const unsigned char *rgba, int width, int height, size_t rowPitch, bool premultiplied = false)
    {
        MipChain chain;
        int levels = MipLevelCount(width, height);
        size_t total = 0;
        for (int k = 1, w = width, h = height; k < levels; k++)
        {
            w = w / 2 > 1 ? w / 2 : 1;
            h = h / 2 > 1 ? h / 2 : 1;
            chain.offsets.push_back(total);
            chain.widths.push_back(w);
            chain.heights.push_back(h);
            total += (size_t)w * (size_t)h * 4;
        }
        chain.bytes.resize(total);
        const unsigned char *src = rgba;
        int srcWidth = width, srcHeight = height;
        size_t srcPitch = rowPitch;
        for (size_t k = 0; k < chain.offsets.size(); k++)
        {
            unsigned char *dst = chain.bytes.data() + chain.offsets[k];
            DownsampleLevel(src, srcWidth, srcHeight, srcPitch, dst, chain.widths[k], chain.heights[k], premultiplied);
            src = dst;
            srcWidth = chain.widths[k];
            srcHeight = chain.heights[k];
            srcPitch = (size_t)srcWidth * 4;
        }
        return chain;
    }
}
END_TEXTURE_MIPS_NAMESPACE
