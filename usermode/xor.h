#pragma once

template <int X> struct EnsureCompileTime {
    enum : int { Value = X };
};

#define Seed ((__TIME__[7] - '0') * 1   + (__TIME__[6] - '0') * 10   + \
              (__TIME__[4] - '0') * 60  + (__TIME__[3] - '0') * 600  + \
              (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)

__forceinline constexpr int LinearCongruentGenerator(int Rounds) {
    return 1013904223 + 1664525 * ((Rounds > 0) ? LinearCongruentGenerator(Rounds - 1) : Seed & 0xFFFFFFFF);
}

#define Random()           EnsureCompileTime<LinearCongruentGenerator(15)>::Value
#define RandomNumber(a, b) (a + (Random() % (b - a + 1)))

template <int... Pack> struct IndexList {};

template <typename IndexList, int Right> struct Append;
template <int... Left, int Right> struct Append<IndexList<Left...>, Right> {
    typedef IndexList<Left..., Right> Result;
};

template <int N> struct ConstructIndexList {
    typedef typename Append<typename ConstructIndexList<N - 1>::Result, N - 1>::Result Result;
};
template <> struct ConstructIndexList<0> {
    typedef IndexList<> Result;
};

const char    XORKEY_A = static_cast<char>(0x13);
const wchar_t XORKEY_W = static_cast<wchar_t>(0x133);

__declspec(noinline) constexpr char EncryptCharA(const char c, int i) {
    return c ^ (XORKEY_A + i);
}

__declspec(noinline) constexpr wchar_t EncryptCharW(const wchar_t c, int i) {
    return c ^ (XORKEY_W + i);
}

template <typename IndexList> class CingA;
template <int... Index> class CingA<IndexList<Index...>> {
    char Value[sizeof...(Index) + 1];
public:
    __forceinline constexpr CingA(const char* const s) : Value{ EncryptCharA(s[Index], Index)... } {}
    __forceinline char* decrypt() {
        for (int i = 0; i < (int)sizeof...(Index); i++)
            Value[i] ^= (XORKEY_A + i);
        Value[sizeof...(Index)] = '\0';
        return Value;
    }
    __forceinline char* get() { return Value; }
};

template <typename IndexList> class CingW;
template <int... Index> class CingW<IndexList<Index...>> {
    wchar_t Value[sizeof...(Index) + 1];
public:
    __forceinline constexpr CingW(const wchar_t* const s) : Value{ EncryptCharW(s[Index], Index)... } {}
    __forceinline wchar_t* decrypt() {
        for (int i = 0; i < (int)sizeof...(Index); i++)
            Value[i] ^= (XORKEY_W + i);
        Value[sizeof...(Index)] = L'\0';
        return Value;
    }
    __forceinline wchar_t* get() { return Value; }
};

#define xor_a(s) (CingA<ConstructIndexList<sizeof(s) - 1>::Result>(s).decrypt())
#define xor_w(s) (CingW<ConstructIndexList<sizeof(s) - 1>::Result>(s).decrypt())
