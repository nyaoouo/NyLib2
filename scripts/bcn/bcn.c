#include <stdint.h>
#include <stddef.h>

__declspec(dllexport) int32_t bcn_decode_bc1(const uint8_t *src, size_t src_len, size_t width, size_t height,
                                         uint8_t *dst, size_t dst_len)
{
    if (!width || !height || width % 4 || height % 4)
        return -1;
    size_t bw = width / 4, bh = height / 4;
    if (bw > SIZE_MAX / 8 / bh || !src || src_len < 8 * bw * bh)
        return -2;
    if (width > SIZE_MAX / 4 / height || !dst || dst_len < width * height * 4)
        return -3;
    size_t stride = width * 4;
    for (size_t by = 0; by < bh; by++)
        for (size_t bx = 0; bx < bw; bx++)
        {
            const uint8_t *b = src + 8 * (by * bw + bx);
            uint32_t c0 = b[0] | (b[1] << 8), c1 = b[2] | (b[3] << 8);
            uint32_t bits = b[4] | (b[5] << 8) | (b[6] << 16) | ((uint32_t)b[7] << 24);
            uint32_t r0 = (c0 >> 11) & 31, g0 = (c0 >> 5) & 63, b0 = c0 & 31;
            uint32_t r1 = (c1 >> 11) & 31, g1 = (c1 >> 5) & 63, b1 = c1 & 31;
            r0 = (r0 << 3) | (r0 >> 2); g0 = (g0 << 2) | (g0 >> 4); b0 = (b0 << 3) | (b0 >> 2);
            r1 = (r1 << 3) | (r1 >> 2); g1 = (g1 << 2) | (g1 >> 4); b1 = (b1 << 3) | (b1 >> 2);
            uint32_t pal[4];
            pal[0] = r0 | (g0 << 8) | (b0 << 16) | 0xFF000000u;
            pal[1] = r1 | (g1 << 8) | (b1 << 16) | 0xFF000000u;
            if (c0 > c1)
            {
                pal[2] = (((2 * r0 + r1) * 683) >> 11) | ((((2 * g0 + g1) * 683) >> 11) << 8) | ((((2 * b0 + b1) * 683) >> 11) << 16) | 0xFF000000u;
                pal[3] = (((r0 + 2 * r1) * 683) >> 11) | ((((g0 + 2 * g1) * 683) >> 11) << 8) | ((((b0 + 2 * b1) * 683) >> 11) << 16) | 0xFF000000u;
            }
            else
            {
                pal[2] = ((r0 + r1) >> 1) | (((g0 + g1) >> 1) << 8) | (((b0 + b1) >> 1) << 16) | 0xFF000000u;
                pal[3] = 0xFF000000u;
            }
            for (size_t py = 0; py < 4; py++)
            {
                uint32_t *row = (uint32_t *)(dst + (by * 4 + py) * stride) + bx * 4;
                row[0] = pal[bits & 3]; row[1] = pal[(bits >> 2) & 3]; row[2] = pal[(bits >> 4) & 3]; row[3] = pal[(bits >> 6) & 3];
                bits >>= 8;
            }
        }
    return 0;
}
