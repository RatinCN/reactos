#include "shelltest.h"

#include <SlimDetours.h>

typedef
BOOL
WINAPI
FN_EqualRect(
    _In_ CONST RECT* lprc1,
    _In_ CONST RECT* lprc2);

PVOID g_pfnEqualRect = NULL;

static
BOOL
WINAPI
Hooked_EqualRect(
    _In_ CONST RECT* lprc1,
    _In_ CONST RECT* lprc2)
{
    trace("Hooked EqualRect enter: lprc1 = (%ld, %ld, %ld, %ld), lprc2 = (%ld, %ld, %ld, %ld)\n",
          lprc1->top,
          lprc1->right,
          lprc1->bottom,
          lprc1->left,
          lprc2->top,
          lprc2->right,
          lprc2->bottom,
          lprc2->left);
    return ((FN_EqualRect*)g_pfnEqualRect)(lprc1, lprc2);
}

START_TEST(SlimDetoursExample)
{
    HRESULT hr;
    HMODULE hUser32;
    RECT rc1 = { 0 }, rc2 = { 0 };

    /* Load user32.dll!EqualRect */
    hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32 == NULL)
    {
        skip("Load user32.dll failed with: 0x%08lX\n", GetLastError());
        return;
    }
    g_pfnEqualRect = (PVOID)GetProcAddress(hUser32, "EqualRect");
    if (g_pfnEqualRect == NULL)
    {
        skip("Load user32.dll!EqualRect failed with: 0x%08lX\n", GetLastError());
        return;
    }

    /* Hook EqualRect and call it */
    hr = SlimDetoursInlineHook(TRUE, &g_pfnEqualRect, (PVOID)Hooked_EqualRect);
    if (FAILED(hr))
    {
        skip("Hook EqualRect failed with: 0x%08lX\n", hr);
        return;
    }
    trace("EqualRect returns %s\n", EqualRect(&rc1, &rc2) ? "TRUE" : "FALSE");
}
