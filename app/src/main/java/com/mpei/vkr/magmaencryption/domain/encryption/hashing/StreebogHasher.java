package com.mpei.vkr.magmaencryption.domain.encryption.hashing;

import com.mpei.vkr.magmaencryption.domain.utils.ArrayHelper;
import com.mpei.vkr.magmaencryption.domain.utils.TypeConverter;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.BitSet;

public class StreebogHasher {

    private final byte[] mBytesToHash;

    //region boxes
    private final byte[] sBox = new byte[]{
            (byte) 0xFC, (byte) 0xEE, (byte) 0xDD, (byte) 0x11, (byte) 0xCF, (byte) 0x6E, (byte) 0x31, (byte) 0x16,
            (byte) 0xFB, (byte) 0xC4, (byte) 0xFA, (byte) 0xDA, (byte) 0x23, (byte) 0xC5, (byte) 0x04, (byte) 0x4D,
            (byte) 0xE9, (byte) 0x77, (byte) 0xF0, (byte) 0xDB, (byte) 0x93, (byte) 0x2E, (byte) 0x99, (byte) 0xBA,
            (byte) 0x17, (byte) 0x36, (byte) 0xF1, (byte) 0xBB, (byte) 0x14, (byte) 0xCD, (byte) 0x5F, (byte) 0xC1,
            (byte) 0xF9, (byte) 0x18, (byte) 0x65, (byte) 0x5A, (byte) 0xE2, (byte) 0x5C, (byte) 0xEF, (byte) 0x21,
            (byte) 0x81, (byte) 0x1C, (byte) 0x3C, (byte) 0x42, (byte) 0x8B, (byte) 0x01, (byte) 0x8E, (byte) 0x4F,
            (byte) 0x05, (byte) 0x84, (byte) 0x02, (byte) 0xAE, (byte) 0xE3, (byte) 0x6A, (byte) 0x8F, (byte) 0xA0,
            (byte) 0x06, (byte) 0x0B, (byte) 0xED, (byte) 0x98, (byte) 0x7F, (byte) 0xD4, (byte) 0xD3, (byte) 0x1F,
            (byte) 0xEB, (byte) 0x34, (byte) 0x2C, (byte) 0x51, (byte) 0xEA, (byte) 0xC8, (byte) 0x48, (byte) 0xAB,
            (byte) 0xF2, (byte) 0x2A, (byte) 0x68, (byte) 0xA2, (byte) 0xFD, (byte) 0x3A, (byte) 0xCE, (byte) 0xCC,
            (byte) 0xB5, (byte) 0x70, (byte) 0x0E, (byte) 0x56, (byte) 0x08, (byte) 0x0C, (byte) 0x76, (byte) 0x12,
            (byte) 0xBF, (byte) 0x72, (byte) 0x13, (byte) 0x47, (byte) 0x9C, (byte) 0xB7, (byte) 0x5D, (byte) 0x87,
            (byte) 0x15, (byte) 0xA1, (byte) 0x96, (byte) 0x29, (byte) 0x10, (byte) 0x7B, (byte) 0x9A, (byte) 0xC7,
            (byte) 0xF3, (byte) 0x91, (byte) 0x78, (byte) 0x6F, (byte) 0x9D, (byte) 0x9E, (byte) 0xB2, (byte) 0xB1,
            (byte) 0x32, (byte) 0x75, (byte) 0x19, (byte) 0x3D, (byte) 0xFF, (byte) 0x35, (byte) 0x8A, (byte) 0x7E,
            (byte) 0x6D, (byte) 0x54, (byte) 0xC6, (byte) 0x80, (byte) 0xC3, (byte) 0xBD, (byte) 0x0D, (byte) 0x57,
            (byte) 0xDF, (byte) 0xF5, (byte) 0x24, (byte) 0xA9, (byte) 0x3E, (byte) 0xA8, (byte) 0x43, (byte) 0xC9,
            (byte) 0xD7, (byte) 0x79, (byte) 0xD6, (byte) 0xF6, (byte) 0x7C, (byte) 0x22, (byte) 0xB9, (byte) 0x03,
            (byte) 0xE0, (byte) 0x0F, (byte) 0xEC, (byte) 0xDE, (byte) 0x7A, (byte) 0x94, (byte) 0xB0, (byte) 0xBC,
            (byte) 0xDC, (byte) 0xE8, (byte) 0x28, (byte) 0x50, (byte) 0x4E, (byte) 0x33, (byte) 0x0A, (byte) 0x4A,
            (byte) 0xA7, (byte) 0x97, (byte) 0x60, (byte) 0x73, (byte) 0x1E, (byte) 0x00, (byte) 0x62, (byte) 0x44,
            (byte) 0x1A, (byte) 0xB8, (byte) 0x38, (byte) 0x82, (byte) 0x64, (byte) 0x9F, (byte) 0x26, (byte) 0x41,
            (byte) 0xAD, (byte) 0x45, (byte) 0x46, (byte) 0x92, (byte) 0x27, (byte) 0x5E, (byte) 0x55, (byte) 0x2F,
            (byte) 0x8C, (byte) 0xA3, (byte) 0xA5, (byte) 0x7D, (byte) 0x69, (byte) 0xD5, (byte) 0x95, (byte) 0x3B,
            (byte) 0x07, (byte) 0x58, (byte) 0xB3, (byte) 0x40, (byte) 0x86, (byte) 0xAC, (byte) 0x1D, (byte) 0xF7,
            (byte) 0x30, (byte) 0x37, (byte) 0x6B, (byte) 0xE4, (byte) 0x88, (byte) 0xD9, (byte) 0xE7, (byte) 0x89,
            (byte) 0xE1, (byte) 0x1B, (byte) 0x83, (byte) 0x49, (byte) 0x4C, (byte) 0x3F, (byte) 0xF8, (byte) 0xFE,
            (byte) 0x8D, (byte) 0x53, (byte) 0xAA, (byte) 0x90, (byte) 0xCA, (byte) 0xD8, (byte) 0x85, (byte) 0x61,
            (byte) 0x20, (byte) 0x71, (byte) 0x67, (byte) 0xA4, (byte) 0x2D, (byte) 0x2B, (byte) 0x09, (byte) 0x5B,
            (byte) 0xCB, (byte) 0x9B, (byte) 0x25, (byte) 0xD0, (byte) 0xBE, (byte) 0xE5, (byte) 0x6C, (byte) 0x52,
            (byte) 0x59, (byte) 0xA6, (byte) 0x74, (byte) 0xD2, (byte) 0xE6, (byte) 0xF4, (byte) 0xB4, (byte) 0xC0,
            (byte) 0xD1, (byte) 0x66, (byte) 0xAF, (byte) 0xC2, (byte) 0x39, (byte) 0x4B, (byte) 0x63, (byte) 0xB6
    };

    private final byte[] permutationBox = new byte[]{
            (byte) 0x00, (byte) 0x08, (byte) 0x10, (byte) 0x18, (byte) 0x20, (byte) 0x28,
            (byte) 0x30, (byte) 0x38, (byte) 0x01, (byte) 0x09, (byte) 0x11, (byte) 0x19, (byte) 0x21, (byte) 0x29, (byte) 0x31, (byte) 0x39,
            (byte) 0x02, (byte) 0x0a, (byte) 0x12, (byte) 0x1a, (byte) 0x22, (byte) 0x2a, (byte) 0x32, (byte) 0x3a, (byte) 0x03, (byte) 0x0b,
            (byte) 0x13, (byte) 0x1b, (byte) 0x23, (byte) 0x2b, (byte) 0x33, (byte) 0x3b, (byte) 0x04, (byte) 0x0c, (byte) 0x14, (byte) 0x1c,
            (byte) 0x24, (byte) 0x2c, (byte) 0x34, (byte) 0x3c, (byte) 0x05, (byte) 0x0d, (byte) 0x15, (byte) 0x1d, (byte) 0x25, (byte) 0x2d,
            (byte) 0x35, (byte) 0x3d, (byte) 0x06, (byte) 0x0e, (byte) 0x16, (byte) 0x1e, (byte) 0x26, (byte) 0x2e,
            (byte) 0x36, (byte) 0x3e, (byte) 0x07, (byte) 0x0f, (byte) 0x17, (byte) 0x1f, (byte) 0x27, (byte) 0x2f, (byte) 0x37, (byte) 0x3f};

    private final long[] matrixA = new long[]{
            0x8e20faa72ba0b470L, 0x47107ddd9b505a38L, 0xad08b0e0c3282d1cL, 0xd8045870ef14980eL, 0x6c022c38f90a4c07L,
            0x3601161cf205268dL, 0x1b8e0b0e798c13c8L, 0x83478b07b2468764L, 0xa011d380818e8f40L, 0x5086e740ce47c920L,
            0x2843fd2067adea10L, 0x14aff010bdd87508L, 0x0ad97808d06cb404L, 0x05e23c0468365a02L, 0x8c711e02341b2d01L,
            0x46b60f011a83988eL, 0x90dab52a387ae76fL, 0x486dd4151c3dfdb9L, 0x24b86a840e90f0d2L, 0x125c354207487869L,
            0x092e94218d243cbaL, 0x8a174a9ec8121e5dL, 0x4585254f64090fa0L, 0xaccc9ca9328a8950L, 0x9d4df05d5f661451L,
            0xc0a878a0a1330aa6L, 0x60543c50de970553L, 0x302a1e286fc58ca7L, 0x18150f14b9ec46ddL, 0x0c84890ad27623e0L,
            0x0642ca05693b9f70L, 0x0321658cba93c138L, 0x86275df09ce8aaa8L, 0x439da0784e745554L, 0xafc0503c273aa42aL,
            0xd960281e9d1d5215L, 0xe230140fc0802984L, 0x71180a8960409a42L, 0xb60c05ca30204d21L, 0x5b068c651810a89eL,
            0x456c34887a3805b9L, 0xac361a443d1c8cd2L, 0x561b0d22900e4669L, 0x2b838811480723baL, 0x9bcf4486248d9f5dL,
            0xc3e9224312c8c1a0L, 0xeffa11af0964ee50L, 0xf97d86d98a327728L, 0xe4fa2054a80b329cL, 0x727d102a548b194eL,
            0x39b008152acb8227L, 0x9258048415eb419dL, 0x492c024284fbaec0L, 0xaa16012142f35760L, 0x550b8e9e21f7a530L,
            0xa48b474f9ef5dc18L, 0x70a6a56e2440598eL, 0x3853dc371220a247L, 0x1ca76e95091051adL, 0x0edd37c48a08a6d8L,
            0x07e095624504536cL, 0x8d70c431ac02a736L, 0xc83862965601dd1bL, 0x641c314b2b8ee083L
    };

    private final byte[][] constantBox = new byte[][]{
            new byte[]{
                    (byte) 0xb1, (byte) 0x08, (byte) 0x5b, (byte) 0xda, (byte) 0x1e, (byte) 0xca, (byte) 0xda, (byte) 0xe9, (byte) 0xeb, (byte) 0xcb, (byte) 0x2f, (byte) 0x81, (byte) 0xc0,
                    (byte) 0x65, (byte) 0x7c, (byte) 0x1f, (byte) 0x2f, (byte) 0x6a, (byte) 0x76, (byte) 0x43, (byte) 0x2e, (byte) 0x45, (byte) 0xd0, (byte) 0x16, (byte) 0x71, (byte) 0x4e,
                    (byte) 0xb8, (byte) 0x8d, (byte) 0x75, (byte) 0x85, (byte) 0xc4, (byte) 0xfc, (byte) 0x4b, (byte) 0x7c, (byte) 0xe0, (byte) 0x91, (byte) 0x92, (byte) 0x67, (byte) 0x69,
                    (byte) 0x01, (byte) 0xa2, (byte) 0x42, (byte) 0x2a, (byte) 0x08, (byte) 0xa4, (byte) 0x60, (byte) 0xd3, (byte) 0x15, (byte) 0x05, (byte) 0x76, (byte) 0x74,
                    (byte) 0x36, (byte) 0xcc, (byte) 0x74, (byte) 0x4d, (byte) 0x23, (byte) 0xdd, (byte) 0x80, (byte) 0x65, (byte) 0x59, (byte) 0xf2, (byte) 0xa6, (byte) 0x45, (byte) 0x07
            },
            new byte[]{
                    (byte) 0x6f, (byte) 0xa3, (byte) 0xb5, (byte) 0x8a, (byte) 0xa9, (byte) 0x9d, (byte) 0x2f, (byte) 0x1a, (byte) 0x4f, (byte) 0xe3, (byte) 0x9d, (byte) 0x46, (byte) 0x0f,
                    (byte) 0x70, (byte) 0xb5, (byte) 0xd7, (byte) 0xf3, (byte) 0xfe, (byte) 0xea, (byte) 0x72, (byte) 0x0a, (byte) 0x23, (byte) 0x2b, (byte) 0x98, (byte) 0x61, (byte) 0xd5,
                    (byte) 0x5e, (byte) 0x0f, (byte) 0x16, (byte) 0xb5, (byte) 0x01, (byte) 0x31, (byte) 0x9a, (byte) 0xb5, (byte) 0x17, (byte) 0x6b, (byte) 0x12, (byte) 0xd6, (byte) 0x99,
                    (byte) 0x58, (byte) 0x5c, (byte) 0xb5, (byte) 0x61, (byte) 0xc2, (byte) 0xdb, (byte) 0x0a, (byte) 0xa7, (byte) 0xca, (byte) 0x55, (byte) 0xdd, (byte) 0xa2,
                    (byte) 0x1b, (byte) 0xd7, (byte) 0xcb, (byte) 0xcd, (byte) 0x56, (byte) 0xe6, (byte) 0x79, (byte) 0x04, (byte) 0x70, (byte) 0x21, (byte) 0xb1, (byte) 0x9b, (byte) 0xb7
            },
            new byte[]{
                    (byte) 0xf5, (byte) 0x74, (byte) 0xdc, (byte) 0xac, (byte) 0x2b, (byte) 0xce, (byte) 0x2f, (byte) 0xc7, (byte) 0x0a, (byte) 0x39, (byte) 0xfc, (byte) 0x28, (byte) 0x6a, (byte) 0x3d,
                    (byte) 0x84, (byte) 0x35, (byte) 0x06, (byte) 0xf1, (byte) 0x5e, (byte) 0x5f, (byte) 0x52, (byte) 0x9c, (byte) 0x1f, (byte) 0x8b, (byte) 0xf2, (byte) 0xea, (byte) 0x75, (byte) 0x14,
                    (byte) 0xb1, (byte) 0x29, (byte) 0x7b, (byte) 0x7b, (byte) 0xd3, (byte) 0xe2, (byte) 0x0f, (byte) 0xe4, (byte) 0x90, (byte) 0x35, (byte) 0x9e, (byte) 0xb1, (byte) 0xc1, (byte) 0xc9,
                    (byte) 0x3a, (byte) 0x37, (byte) 0x60, (byte) 0x62, (byte) 0xdb, (byte) 0x09, (byte) 0xc2, (byte) 0xb6,
                    (byte) 0xf4, (byte) 0x43, (byte) 0x86, (byte) 0x7a, (byte) 0xdb, (byte) 0x31, (byte) 0x99, (byte) 0x1e, (byte) 0x96, (byte) 0xf5, (byte) 0x0a, (byte) 0xba, (byte) 0x0a, (byte) 0xb2
            },
            new byte[]{
                    (byte) 0xef, (byte) 0x1f, (byte) 0xdf, (byte) 0xb3, (byte) 0xe8, (byte) 0x15, (byte) 0x66, (byte) 0xd2, (byte) 0xf9, (byte) 0x48, (byte) 0xe1, (byte) 0xa0, (byte) 0x5d, (byte) 0x71,
                    (byte) 0xe4, (byte) 0xdd, (byte) 0x48, (byte) 0x8e, (byte) 0x85, (byte) 0x7e, (byte) 0x33, (byte) 0x5c, (byte) 0x3c, (byte) 0x7d, (byte) 0x9d, (byte) 0x72, (byte) 0x1c, (byte) 0xad,
                    (byte) 0x68, (byte) 0x5e, (byte) 0x35, (byte) 0x3f, (byte) 0xa9, (byte) 0xd7, (byte) 0x2c, (byte) 0x82, (byte) 0xed, (byte) 0x03, (byte) 0xd6, (byte) 0x75, (byte) 0xd8, (byte) 0xb7,
                    (byte) 0x13, (byte) 0x33, (byte) 0x93, (byte) 0x52, (byte) 0x03, (byte) 0xbe, (byte) 0x34, (byte) 0x53,
                    (byte) 0xea, (byte) 0xa1, (byte) 0x93, (byte) 0xe8, (byte) 0x37, (byte) 0xf1, (byte) 0x22, (byte) 0x0c, (byte) 0xbe, (byte) 0xbc, (byte) 0x84, (byte) 0xe3, (byte) 0xd1, (byte) 0x2e

            },
            new byte[]{
                    (byte) 0x4b, (byte) 0xea, (byte) 0x6b, (byte) 0xac, (byte) 0xad, (byte) 0x47, (byte) 0x47, (byte) 0x99, (byte) 0x9a, (byte) 0x3f, (byte) 0x41, (byte) 0x0c, (byte) 0x6c, (byte) 0xa9,
                    (byte) 0x23, (byte) 0x63, (byte) 0x7f, (byte) 0x15, (byte) 0x1c, (byte) 0x1f, (byte) 0x16, (byte) 0x86, (byte) 0x10, (byte) 0x4a, (byte) 0x35, (byte) 0x9e, (byte) 0x35, (byte) 0xd7,
                    (byte) 0x80, (byte) 0x0f, (byte) 0xff, (byte) 0xbd, (byte) 0xbf, (byte) 0xcd, (byte) 0x17, (byte) 0x47, (byte) 0x25, (byte) 0x3a, (byte) 0xf5, (byte) 0xa3, (byte) 0xdf, (byte) 0xff,
                    (byte) 0x00, (byte) 0xb7, (byte) 0x23, (byte) 0x27, (byte) 0x1a, (byte) 0x16, (byte) 0x7a, (byte) 0x56,
                    (byte) 0xa2, (byte) 0x7e, (byte) 0xa9, (byte) 0xea, (byte) 0x63, (byte) 0xf5, (byte) 0x60, (byte) 0x17, (byte) 0x58, (byte) 0xfd, (byte) 0x7c, (byte) 0x6c, (byte) 0xfe, (byte) 0x57
            },
            new byte[]{
                    (byte) 0xae, (byte) 0x4f, (byte) 0xae, (byte) 0xae, (byte) 0x1d, (byte) 0x3a, (byte) 0xd3, (byte) 0xd9, (byte) 0x6f, (byte) 0xa4, (byte) 0xc3, (byte) 0x3b, (byte) 0x7a, (byte) 0x30,
                    (byte) 0x39, (byte) 0xc0, (byte) 0x2d, (byte) 0x66, (byte) 0xc4, (byte) 0xf9, (byte) 0x51, (byte) 0x42, (byte) 0xa4, (byte) 0x6c, (byte) 0x18, (byte) 0x7f, (byte) 0x9a, (byte) 0xb4,
                    (byte) 0x9a, (byte) 0xf0, (byte) 0x8e, (byte) 0xc6, (byte) 0xcf, (byte) 0xfa, (byte) 0xa6, (byte) 0xb7, (byte) 0x1c, (byte) 0x9a, (byte) 0xb7, (byte) 0xb4, (byte) 0x0a, (byte) 0xf2,
                    (byte) 0x1f, (byte) 0x66, (byte) 0xc2, (byte) 0xbe, (byte) 0xc6, (byte) 0xb6, (byte) 0xbf, (byte) 0x71,
                    (byte) 0xc5, (byte) 0x72, (byte) 0x36, (byte) 0x90, (byte) 0x4f, (byte) 0x35, (byte) 0xfa, (byte) 0x68, (byte) 0x40, (byte) 0x7a, (byte) 0x46, (byte) 0x64, (byte) 0x7d, (byte) 0x6e
            },
            new byte[]{
                    (byte) 0xf4, (byte) 0xc7, (byte) 0x0e, (byte) 0x16, (byte) 0xee, (byte) 0xaa, (byte) 0xc5, (byte) 0xec, (byte) 0x51, (byte) 0xac, (byte) 0x86, (byte) 0xfe, (byte) 0xbf, (byte) 0x24,
                    (byte) 0x09, (byte) 0x54, (byte) 0x39, (byte) 0x9e, (byte) 0xc6, (byte) 0xc7, (byte) 0xe6, (byte) 0xbf, (byte) 0x87, (byte) 0xc9, (byte) 0xd3, (byte) 0x47, (byte) 0x3e, (byte) 0x33,
                    (byte) 0x19, (byte) 0x7a, (byte) 0x93, (byte) 0xc9, (byte) 0x09, (byte) 0x92, (byte) 0xab, (byte) 0xc5, (byte) 0x2d, (byte) 0x82, (byte) 0x2c, (byte) 0x37, (byte) 0x06, (byte) 0x47,
                    (byte) 0x69, (byte) 0x83, (byte) 0x28, (byte) 0x4a, (byte) 0x05, (byte) 0x04, (byte) 0x35, (byte) 0x17,
                    (byte) 0x45, (byte) 0x4c, (byte) 0xa2, (byte) 0x3c, (byte) 0x4a, (byte) 0xf3, (byte) 0x88, (byte) 0x86, (byte) 0x56, (byte) 0x4d, (byte) 0x3a, (byte) 0x14, (byte) 0xd4, (byte) 0x93
            },
            new byte[]{
                    (byte) 0x9b, (byte) 0x1f, (byte) 0x5b, (byte) 0x42, (byte) 0x4d, (byte) 0x93, (byte) 0xc9, (byte) 0xa7, (byte) 0x03, (byte) 0xe7, (byte) 0xaa, (byte) 0x02, (byte) 0x0c, (byte) 0x6e,
                    (byte) 0x41, (byte) 0x41, (byte) 0x4e, (byte) 0xb7, (byte) 0xf8, (byte) 0x71, (byte) 0x9c, (byte) 0x36, (byte) 0xde, (byte) 0x1e, (byte) 0x89, (byte) 0xb4, (byte) 0x44, (byte) 0x3b,
                    (byte) 0x4d, (byte) 0xdb, (byte) 0xc4, (byte) 0x9a, (byte) 0xf4, (byte) 0x89, (byte) 0x2b, (byte) 0xcb, (byte) 0x92, (byte) 0x9b, (byte) 0x06, (byte) 0x90, (byte) 0x69, (byte) 0xd1,
                    (byte) 0x8d, (byte) 0x2b, (byte) 0xd1, (byte) 0xa5, (byte) 0xc4, (byte) 0x2f, (byte) 0x36, (byte) 0xac,
                    (byte) 0xc2, (byte) 0x35, (byte) 0x59, (byte) 0x51, (byte) 0xa8, (byte) 0xd9, (byte) 0xa4, (byte) 0x7f, (byte) 0x0d, (byte) 0xd4, (byte) 0xbf, (byte) 0x02, (byte) 0xe7, (byte) 0x1e
            },
            new byte[]{
                    (byte) 0x37, (byte) 0x8f, (byte) 0x5a, (byte) 0x54, (byte) 0x16, (byte) 0x31, (byte) 0x22, (byte) 0x9b, (byte) 0x94, (byte) 0x4c, (byte) 0x9a, (byte) 0xd8, (byte) 0xec, (byte) 0x16,
                    (byte) 0x5f, (byte) 0xde, (byte) 0x3a, (byte) 0x7d, (byte) 0x3a, (byte) 0x1b, (byte) 0x25, (byte) 0x89, (byte) 0x42, (byte) 0x24, (byte) 0x3c, (byte) 0xd9, (byte) 0x55, (byte) 0xb7,
                    (byte) 0xe0, (byte) 0x0d, (byte) 0x09, (byte) 0x84, (byte) 0x80, (byte) 0x0a, (byte) 0x44, (byte) 0x0b, (byte) 0xdb, (byte) 0xb2, (byte) 0xce, (byte) 0xb1, (byte) 0x7b, (byte) 0x2b,
                    (byte) 0x8a, (byte) 0x9a, (byte) 0xa6, (byte) 0x07, (byte) 0x9c, (byte) 0x54, (byte) 0x0e, (byte) 0x38,
                    (byte) 0xdc, (byte) 0x92, (byte) 0xcb, (byte) 0x1f, (byte) 0x2a, (byte) 0x60, (byte) 0x72, (byte) 0x61, (byte) 0x44, (byte) 0x51, (byte) 0x83, (byte) 0x23, (byte) 0x5a, (byte) 0xdb
            },
            new byte[]{
                    (byte) 0xab, (byte) 0xbe, (byte) 0xde, (byte) 0xa6, (byte) 0x80, (byte) 0x05, (byte) 0x6f, (byte) 0x52, (byte) 0x38, (byte) 0x2a, (byte) 0xe5, (byte) 0x48, (byte) 0xb2, (byte) 0xe4,
                    (byte) 0xf3, (byte) 0xf3, (byte) 0x89, (byte) 0x41, (byte) 0xe7, (byte) 0x1c, (byte) 0xff, (byte) 0x8a, (byte) 0x78, (byte) 0xdb, (byte) 0x1f, (byte) 0xff,
                    (byte) 0xe1, (byte) 0x8a, (byte) 0x1b, (byte) 0x33, (byte) 0x61, (byte) 0x03, (byte) 0x9f, (byte) 0xe7, (byte) 0x67, (byte) 0x02, (byte) 0xaf, (byte) 0x69, (byte) 0x33, (byte) 0x4b,
                    (byte) 0x7a, (byte) 0x1e, (byte) 0x6c, (byte) 0x30, (byte) 0x3b, (byte) 0x76, (byte) 0x52, (byte) 0xf4, (byte) 0x36, (byte) 0x98,
                    (byte) 0xfa, (byte) 0xd1, (byte) 0x15, (byte) 0x3b, (byte) 0xb6, (byte) 0xc3, (byte) 0x74, (byte) 0xb4, (byte) 0xc7, (byte) 0xfb, (byte) 0x98, (byte) 0x45, (byte) 0x9c, (byte) 0xed
            },
            new byte[]{
                    (byte) 0x7b, (byte) 0xcd, (byte) 0x9e, (byte) 0xd0, (byte) 0xef, (byte) 0xc8, (byte) 0x89, (byte) 0xfb, (byte) 0x30, (byte) 0x02, (byte) 0xc6, (byte) 0xcd, (byte) 0x63,
                    (byte) 0x5a, (byte) 0xfe, (byte) 0x94, (byte) 0xd8, (byte) 0xfa, (byte) 0x6b, (byte) 0xbb, (byte) 0xeb, (byte) 0xab, (byte) 0x07, (byte) 0x61, (byte) 0x20, (byte) 0x01,
                    (byte) 0x80, (byte) 0x21, (byte) 0x14, (byte) 0x84, (byte) 0x66, (byte) 0x79, (byte) 0x8a, (byte) 0x1d, (byte) 0x71, (byte) 0xef, (byte) 0xea, (byte) 0x48, (byte) 0xb9,
                    (byte) 0xca, (byte) 0xef, (byte) 0xba, (byte) 0xcd, (byte) 0x1d, (byte) 0x7d, (byte) 0x47, (byte) 0x6e, (byte) 0x98, (byte) 0xde, (byte) 0xa2,
                    (byte) 0x59, (byte) 0x4a, (byte) 0xc0, (byte) 0x6f, (byte) 0xd8, (byte) 0x5d, (byte) 0x6b, (byte) 0xca, (byte) 0xa4, (byte) 0xcd, (byte) 0x81, (byte) 0xf3, (byte) 0x2d, (byte) 0x1b
            },
            new byte[]{
                    (byte) 0x37, (byte) 0x8e, (byte) 0xe7, (byte) 0x67, (byte) 0xf1, (byte) 0x16, (byte) 0x31, (byte) 0xba, (byte) 0xd2, (byte) 0x13, (byte) 0x80, (byte) 0xb0, (byte) 0x04,
                    (byte) 0x49, (byte) 0xb1, (byte) 0x7a, (byte) 0xcd, (byte) 0xa4, (byte) 0x3c, (byte) 0x32, (byte) 0xbc, (byte) 0xdf, (byte) 0x1d, (byte) 0x77, (byte) 0xf8, (byte) 0x20,
                    (byte) 0x12, (byte) 0xd4, (byte) 0x30, (byte) 0x21, (byte) 0x9f, (byte) 0x9b, (byte) 0x5d, (byte) 0x80, (byte) 0xef, (byte) 0x9d, (byte) 0x18, (byte) 0x91, (byte) 0xcc,
                    (byte) 0x86, (byte) 0xe7, (byte) 0x1d, (byte) 0xa4, (byte) 0xaa, (byte) 0x88, (byte) 0xe1, (byte) 0x28, (byte) 0x52, (byte) 0xfa, (byte) 0xf4, (byte) 0x17,
                    (byte) 0xd5, (byte) 0xd9, (byte) 0xb2, (byte) 0x1b, (byte) 0x99, (byte) 0x48, (byte) 0xbc, (byte) 0x92, (byte) 0x4a, (byte) 0xf1, (byte) 0x1b, (byte) 0xd7, (byte) 0x20
            }
    };

    //endregion boxes

    public StreebogHasher(byte[] bytesToHash) {
        mBytesToHash = bytesToHash;
    }

    public StreebogHasher(String bytesToHash) {
        this(bytesToHash, (StandardCharsets.UTF_8));
    }

    public StreebogHasher(String bytesToHash, Charset charset) {
        mBytesToHash = bytesToHash != null ?
                bytesToHash.getBytes(charset) : new byte[0];
    }

    public byte[] generate256Hash() {
        byte[] res = new byte[32];

        byte[] resOfFun = getHash(
                mBytesToHash.length >= 64 ? mBytesToHash : supplementBlockTo64Bytes(mBytesToHash),
                getInitVectorFor256Hash());
        System.arraycopy(resOfFun, 0, res, 0, 32);
        return res;
    }

    public byte[] generate512Hash() {
        return getHash(mBytesToHash, getEmptyByteArrayOfSize64());
    }

    private byte[] getHash(byte[] inputArray, byte[] initVector) {
        byte[] initVectorH = initVector;
        byte[] length = getEmptyByteArrayOfSize64();
        byte[] sigmaSum = getEmptyByteArrayOfSize64();

        byte[] currentBlock;

        int countOfFullBlocks = inputArray.length / 64;

        int remainderOfDiv = inputArray.length % 64;


        for (int i = 0; i < countOfFullBlocks; i++) {
            currentBlock = new byte[64];
            System.arraycopy(inputArray, inputArray.length - (i + 1) * 64, currentBlock, 0, 64);
            initVectorH = compressionFunction(initVectorH, currentBlock, length);

            length = sumByteArrayAndInt(length, 512);

            sigmaSum = sumTwoByteArrays512(sigmaSum, currentBlock);
        }
        if (remainderOfDiv != 0) {
            byte[] blockToSupply = new byte[remainderOfDiv];
            System.arraycopy(inputArray, 0, blockToSupply, 0, remainderOfDiv);
            currentBlock = supplementIncompleteBlockByAlgorithm(blockToSupply);
            initVectorH = compressionFunction(initVectorH, currentBlock, length);
            length = sumByteArrayAndInt(length, remainderOfDiv * 8);

            sigmaSum = sumTwoByteArrays512(sigmaSum, currentBlock);
        }
        initVectorH = compressionFunction(initVectorH, length, getEmptyByteArrayOfSize64());

        initVectorH = compressionFunction(initVectorH, sigmaSum, getEmptyByteArrayOfSize64());

        return initVectorH;
    }

    private byte[] sumByteArrayAndInt(byte[] firstArray, int intValue) {
        BigInteger biSigma2 = new BigInteger(firstArray);
        BigInteger biCurrBlock2 = BigInteger.valueOf(intValue);
        firstArray = biSigma2.add(biCurrBlock2).toByteArray();
        byte[] resArray = new byte[64];
        System.arraycopy(firstArray, 0, resArray, resArray.length - firstArray.length, firstArray.length);
        return resArray;
    }

    private byte[] sumTwoByteArrays512(byte[] firstArray, byte[] secondArray) {
        BigInteger bigInt1 = new BigInteger(1, firstArray);
        BigInteger bigInt2 = new BigInteger(1, secondArray);
        BigInteger mod = BigInteger.valueOf(2).pow(512);
        BigInteger sum = bigInt1.add(bigInt2).mod(mod);
        byte[] resultBytes = sum.toByteArray();
        if (resultBytes.length > 64) {
            byte[] cutedArray = new byte[64];
            System.arraycopy(resultBytes, 0, cutedArray, 0, 64);
            return cutedArray;
        } else if (resultBytes.length < 64){
            byte[] addedArray = new byte[64];
            System.arraycopy(resultBytes, 0, addedArray, 64-resultBytes.length, resultBytes.length);
            return addedArray;
        } else {
            return resultBytes;
        }
    }

    private byte[] getEmptyByteArrayOfSize64() {
        return new byte[64];
    }

    private byte[] getInitVectorFor256Hash() {
        byte[] res = new byte[64];
        Arrays.fill(res, (byte) 0x01);
        return res;
    }

    private byte[] supplementIncompleteBlockByAlgorithm(byte[] blockToSupplement) {
        byte[] res = new byte[64];
        System.arraycopy(blockToSupplement, 0, res, 64 - blockToSupplement.length, blockToSupplement.length);
        res[63 - blockToSupplement.length] = 0x01;
        return res;
    }

    private byte[] supplementBlockTo64Bytes(byte[] blockToSupplement) {
        byte[] res = new byte[64];
        System.arraycopy(blockToSupplement, 0, res, 64 - blockToSupplement.length, blockToSupplement.length);
        return res;
    }

    /**
     * Сложение по модулю 2 двух байтовых массивов одинаковой длины
     *
     * @param firstArray  первый массив
     * @param secondArray второй массив
     * @return результат xor'a
     */
    private byte[] xorTwoByteArrays(byte[] firstArray, byte[] secondArray) {
        byte[] result = new byte[firstArray.length];
        for (int i = 0; i < firstArray.length; i++) {
            result[i] = (byte) (firstArray[i] ^ secondArray[i]);
        }
        return result;
    }

    private byte[] sTransformation(byte[] inputByteArray) {
        byte[] res = new byte[64];
        for (int i = 0; i < res.length; i++) {
            res[i] = sBox[inputByteArray[i] & 0xFF];
        }
        return res;
    }

    private byte[] pTransformation(byte[] inputByteArray) {
        byte[] res = new byte[64];
        for (int i = 0; i < res.length; i++) {
            res[i] = inputByteArray[permutationBox[i]];//sBox[inputByteArray[i] & 0xFF];
        }
        return res;
    }

    private byte[] lTransformation(byte[] inputByteArray) {
        byte[] res = new byte[64];
        for (int i = 0; i < inputByteArray.length; i += 8) {
            byte[] currentSlice = new byte[8];
            System.arraycopy(inputByteArray, i, currentSlice, 0, 8);
            BitSet bitSet = BitSet.valueOf(ArrayHelper.reverseArray(currentSlice));
            long currentLong = 0;
            for (int k = bitSet.nextSetBit(0); k != -1; k = bitSet.nextSetBit(k + 1)) {
                currentLong ^= matrixA[63 - k];
            }
            System.arraycopy(TypeConverter.createBytesFromLong(currentLong), 0, res, i, 8);
        }
        return res;
    }

    private byte[] keySchedule(byte[] inputByteArray, int constNumber) {
        byte[] res;
        res = xorTwoByteArrays(inputByteArray, constantBox[constNumber]);
        res = sTransformation(res);
        res = pTransformation(res);
        res = lTransformation(res);
        return res;
    }

    private byte[] eTransformation(byte[] inputK_Array, byte[] mArray) {
        byte[] state = mArray;
        byte[] kArray = inputK_Array;
        for (int i = 0; i <= 11; i++) {
            state = xorTwoByteArrays(state, kArray);
            state = sTransformation(state);
            state = pTransformation(state);
            state = lTransformation(state);
            kArray = keySchedule(kArray, i);
        }
        state = xorTwoByteArrays(state, kArray);

        return state;
    }


    private byte[] compressionFunction(byte[] initVector, byte[] messageArray, byte[] lengthArray) {
        byte[] result;
        result = xorTwoByteArrays(initVector, lengthArray);
        result = sTransformation(result);
        result = pTransformation(result);
        result = lTransformation(result);
        byte[] eTransformationRes = eTransformation(result, messageArray);
        result = xorTwoByteArrays(eTransformationRes, initVector);
        result = xorTwoByteArrays(result, messageArray);
        return result;
    }

}
