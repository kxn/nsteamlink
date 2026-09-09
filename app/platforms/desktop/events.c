#include "events_backend.h"
static bool foreground = true, quit;
void sl_events_init(void) {
    foreground = true;
    quit = false;
}
bool sl_events_foreground(void) {
    return foreground;
}
bool sl_events_exit_requested(void) {
    return quit;
}
bool sl_events_next(SDL_Event *event) {
    if (!SDL_PollEvent(event))
        return false;
    if (event->type == SDL_QUIT)
        quit = true;
    if (event->type == SDL_WINDOWEVENT) {
        if (event->window.event == SDL_WINDOWEVENT_FOCUS_LOST ||
            event->window.event == SDL_WINDOWEVENT_MINIMIZED)
            foreground = false;
        if (event->window.event == SDL_WINDOWEVENT_FOCUS_GAINED ||
            event->window.event == SDL_WINDOWEVENT_RESTORED)
            foreground = true;
    }
    if (event->type == SDL_APP_WILLENTERBACKGROUND || event->type == SDL_APP_DIDENTERBACKGROUND)
        foreground = false;
    if (event->type == SDL_APP_DIDENTERFOREGROUND)
        foreground = true;
    return true;
}
