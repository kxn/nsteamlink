#include "sdl_input.h"
#include "media.h"
#include "platform/system.h"
#include <SDL.h>
static int keyboard(SDL_Keycode key) {
    switch (key) {
    case SDLK_RETURN:
    case SDLK_a:
        return SL_KEY_A;
    case SDLK_ESCAPE:
    case SDLK_b:
        return SL_KEY_B;
    case SDLK_x:
        return SL_KEY_X;
    case SDLK_y:
        return SL_KEY_Y;
    case SDLK_q:
        return SL_KEY_L;
    case SDLK_e:
        return SL_KEY_R;
    case SDLK_MINUS:
        return SL_KEY_MINUS;
    case SDLK_EQUALS:
        return SL_KEY_PLUS;
    case SDLK_UP:
        return SL_KEY_UP;
    case SDLK_DOWN:
        return SL_KEY_DOWN;
    case SDLK_LEFT:
        return SL_KEY_LEFT;
    case SDLK_RIGHT:
        return SL_KEY_RIGHT;
    default:
        return -1;
    }
}
void sl_sdl_input(const void *native, void *ctx) {
    const SDL_Event *e = native;
    sl_input_router *router = ctx;
    sl_ui_model *ui = router->ui;
    sl_input_event in = {0};
    bool valid = true;
    switch (e->type) {
    case SDL_CONTROLLERBUTTONDOWN:
    case SDL_CONTROLLERBUTTONUP:
        in.type = SL_BUTTON;
        in.device = e->cbutton.which;
        in.code = e->cbutton.button;
        in.value = e->cbutton.state;
        break;
    case SDL_CONTROLLERAXISMOTION:
        in.type = SL_AXIS;
        in.device = e->caxis.which;
        in.code = e->caxis.axis;
        in.value = e->caxis.value;
        break;
    case SDL_KEYDOWN:
    case SDL_KEYUP:
        if (e->key.repeat)
            return;
        if (e->type == SDL_KEYDOWN && (ui->page == SL_PIN || ui->page == SL_MANUAL)) {
            if (e->key.keysym.sym >= '0' && e->key.keysym.sym <= '9') {
                sl_ui_action(ui, SL_DIGIT, e->key.keysym.sym);
                return;
            }
            if (e->key.keysym.sym == SDLK_PERIOD) {
                sl_ui_action(ui, SL_DIGIT, '.');
                return;
            }
            if (e->key.keysym.sym == SDLK_BACKSPACE) {
                sl_ui_action(ui, SL_ERASE, 0);
                return;
            }
        }
        in.type = SL_BUTTON;
        in.code = keyboard(e->key.keysym.sym);
        in.value = e->type == SDL_KEYDOWN;
        valid = in.code >= 0;
        break;
    case SDL_FINGERDOWN:
    case SDL_FINGERUP:
    case SDL_FINGERMOTION:
        in.type = e->type == SDL_FINGERDOWN ? SL_TOUCH_DOWN
                  : e->type == SDL_FINGERUP ? SL_TOUCH_UP
                                            : SL_TOUCH_MOVE;
        in.finger = e->tfinger.fingerId;
        in.x = e->tfinger.x;
        in.y = e->tfinger.y;
        break;
    case SDL_MOUSEBUTTONDOWN:
    case SDL_MOUSEBUTTONUP:
    case SDL_MOUSEMOTION: {
        if ((e->type == SDL_MOUSEMOTION ? e->motion.which : e->button.which) == SDL_TOUCH_MOUSEID)
            return;
        if (e->type != SDL_MOUSEMOTION && e->button.button != SDL_BUTTON_LEFT)
            return;
        in.type = e->type == SDL_MOUSEBUTTONDOWN ? SL_TOUCH_DOWN
                  : e->type == SDL_MOUSEBUTTONUP ? SL_TOUCH_UP
                                                 : SL_TOUCH_MOVE;
        in.finger = INT64_MIN;
        in.x = (e->type == SDL_MOUSEMOTION ? e->motion.x : e->button.x) / 1280.0f;
        in.y = (e->type == SDL_MOUSEMOTION ? e->motion.y : e->button.y) / 720.0f;
        break;
    }
    case SDL_CONTROLLERDEVICEREMOVED:
        in.type = SL_FOCUS_LOST;
        break;
    case SDL_WINDOWEVENT:
        if (e->window.event == SDL_WINDOWEVENT_FOCUS_LOST)
            in.type = SL_FOCUS_LOST;
        else
            valid = false;
        break;
    default:
        valid = false;
        break;
    }
    if (valid)
        sl_input_event_handle(router, &in, sl_system_now());
    sl_media_gate(sl_ui_remote(ui));
}
