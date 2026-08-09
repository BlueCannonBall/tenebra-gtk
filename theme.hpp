#pragma once

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#endif

// Semantic button colours, shared so the accent is defined in exactly one place
#define TENEBRA_ACCENT           fl_rgb_color(0, 120, 215)
#define TENEBRA_ACCENT_PRESSED   fl_rgb_color(0, 86, 179)
#define TENEBRA_DANGER           fl_rgb_color(220, 53, 69)
#define TENEBRA_DANGER_PRESSED   fl_rgb_color(200, 35, 51)

bool is_dark_mode();
void configure_fltk_colors();
#ifdef _WIN32
void set_window_dark_mode(HWND window, bool value = is_dark_mode());
#endif
