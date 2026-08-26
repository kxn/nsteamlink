// Based on devkitPro's graphics/opengl/simple_triangle example.
// Diagnostic changes: stage file, nxlink log socket, and bounded auto-exit.
#include <errno.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <switch.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <glad/glad.h>

#define STAGE_DIR  "sdmc:/switch/nsteamlink"
#define STAGE_PATH STAGE_DIR "/gfx_probe_stage.txt"
#define PROBE_NAME "switch-gfx-gl-official"
#define AUTO_FRAMES 180

static int s_log_fd = -1;

static void ensure_stage_dir(void)
{
    if (mkdir(STAGE_DIR, 0777) != 0 && errno != EEXIST)
        return;
}

static void write_stage(const char *stage)
{
    ensure_stage_dir();
    FILE *fp = fopen(STAGE_PATH, "w");
    if (fp) {
        fprintf(fp, "%s:%s\n", PROBE_NAME, stage);
        fclose(fp);
    }
    if (s_log_fd >= 0)
        dprintf(s_log_fd, "%s: %s\n", PROBE_NAME, stage);
}

static void logline(const char *fmt, ...)
{
    if (s_log_fd < 0)
        return;

    va_list ap;
    va_start(ap, fmt);
    dprintf(s_log_fd, "%s: ", PROBE_NAME);
    vdprintf(s_log_fd, fmt, ap);
    dprintf(s_log_fd, "\n");
    va_end(ap);
}

static void init_log(void)
{
    write_stage("socket:init:start");
    if (R_FAILED(socketInitializeDefault())) {
        write_stage("socket:init:failed");
        return;
    }
    write_stage("socket:init:done");
    write_stage("nxlink:connect:start");
    s_log_fd = nxlinkConnectToHost(false, false);
    write_stage(s_log_fd >= 0 ? "nxlink:connect:done" : "nxlink:connect:failed");
}

static void close_log(void)
{
    if (s_log_fd >= 0) {
        int fd = s_log_fd;
        s_log_fd = -1;
        close(fd);
    }
    socketExit();
}

static EGLDisplay s_display;
static EGLContext s_context;
static EGLSurface s_surface;

static bool initEgl(NWindow* win)
{
    write_stage("egl:get-display:start");
    s_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!s_display) {
        logline("Could not connect to display! error: %d", eglGetError());
        write_stage("egl:get-display:failed");
        goto _fail0;
    }
    write_stage("egl:get-display:done");

    write_stage("egl:initialize:start");
    eglInitialize(s_display, nullptr, nullptr);
    write_stage("egl:initialize:done");

    write_stage("egl:bind-api:start");
    if (eglBindAPI(EGL_OPENGL_API) == EGL_FALSE) {
        logline("Could not set API! error: %d", eglGetError());
        write_stage("egl:bind-api:failed");
        goto _fail1;
    }
    write_stage("egl:bind-api:done");

    EGLConfig config;
    EGLint numConfigs;
    static const EGLint framebufferAttributeList[] =
    {
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_RED_SIZE,     8,
        EGL_GREEN_SIZE,   8,
        EGL_BLUE_SIZE,    8,
        EGL_ALPHA_SIZE,   8,
        EGL_DEPTH_SIZE,   24,
        EGL_STENCIL_SIZE, 8,
        EGL_NONE
    };
    write_stage("egl:choose-config:start");
    eglChooseConfig(s_display, framebufferAttributeList, &config, 1, &numConfigs);
    if (numConfigs == 0) {
        logline("No config found! error: %d", eglGetError());
        write_stage("egl:choose-config:failed");
        goto _fail1;
    }
    write_stage("egl:choose-config:done");

    write_stage("egl:create-surface:start");
    s_surface = eglCreateWindowSurface(s_display, config, win, nullptr);
    if (!s_surface) {
        logline("Surface creation failed! error: %d", eglGetError());
        write_stage("egl:create-surface:failed");
        goto _fail1;
    }
    write_stage("egl:create-surface:done");

    static const EGLint contextAttributeList[] =
    {
        EGL_CONTEXT_OPENGL_PROFILE_MASK_KHR, EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT_KHR,
        EGL_CONTEXT_MAJOR_VERSION_KHR, 4,
        EGL_CONTEXT_MINOR_VERSION_KHR, 3,
        EGL_NONE
    };
    write_stage("egl:create-context:start");
    s_context = eglCreateContext(s_display, config, EGL_NO_CONTEXT, contextAttributeList);
    if (!s_context) {
        logline("Context creation failed! error: %d", eglGetError());
        write_stage("egl:create-context:failed");
        goto _fail2;
    }
    write_stage("egl:create-context:done");

    write_stage("egl:make-current:start");
    eglMakeCurrent(s_display, s_surface, s_surface, s_context);
    write_stage("egl:make-current:done");
    return true;

_fail2:
    eglDestroySurface(s_display, s_surface);
    s_surface = nullptr;
_fail1:
    eglTerminate(s_display);
    s_display = nullptr;
_fail0:
    return false;
}

static void deinitEgl()
{
    if (s_display) {
        write_stage("egl:cleanup:start");
        eglMakeCurrent(s_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        if (s_context) {
            eglDestroyContext(s_display, s_context);
            s_context = nullptr;
        }
        if (s_surface) {
            eglDestroySurface(s_display, s_surface);
            s_surface = nullptr;
        }
        eglTerminate(s_display);
        s_display = nullptr;
        write_stage("egl:cleanup:done");
    }
}

static void setMesaConfig()
{
    // Official example keeps these disabled by default.
    // setenv("EGL_LOG_LEVEL", "debug", 1);
    // setenv("MESA_VERBOSE", "all", 1);
    // setenv("NOUVEAU_MESA_DEBUG", "1", 1);
}

static const char* const vertexShaderSource = R"text(
    #version 330 core

    layout (location = 0) in vec3 aPos;
    layout (location = 1) in vec3 aColor;

    out vec3 ourColor;

    void main()
    {
        gl_Position = vec4(aPos.x, aPos.y, aPos.z, 1.0);
        ourColor = aColor;
    }
)text";

static const char* const fragmentShaderSource = R"text(
    #version 330 core

    in vec3 ourColor;

    out vec4 fragColor;

    void main()
    {
        fragColor = vec4(ourColor, 1.0f);
    }
)text";

static GLuint createAndCompileShader(GLenum type, const char* source)
{
    GLint success;
    GLchar msg[512];

    GLuint handle = glCreateShader(type);
    if (!handle) {
        logline("%u: cannot create shader", type);
        return 0;
    }
    glShaderSource(handle, 1, &source, nullptr);
    glCompileShader(handle);
    glGetShaderiv(handle, GL_COMPILE_STATUS, &success);

    if (!success) {
        glGetShaderInfoLog(handle, sizeof(msg), nullptr, msg);
        logline("%u: %s", type, msg);
        glDeleteShader(handle);
        return 0;
    }

    return handle;
}

static GLuint s_program;
static GLuint s_vao, s_vbo;

static void sceneInit()
{
    write_stage("scene:init:start");
    GLint vsh = createAndCompileShader(GL_VERTEX_SHADER, vertexShaderSource);
    GLint fsh = createAndCompileShader(GL_FRAGMENT_SHADER, fragmentShaderSource);

    s_program = glCreateProgram();
    glAttachShader(s_program, vsh);
    glAttachShader(s_program, fsh);
    glLinkProgram(s_program);

    GLint success;
    glGetProgramiv(s_program, GL_LINK_STATUS, &success);
    if (!success) {
        char buf[512];
        glGetProgramInfoLog(s_program, sizeof(buf), nullptr, buf);
        logline("Link error: %s", buf);
    }
    glDeleteShader(vsh);
    glDeleteShader(fsh);

    struct Vertex
    {
        float position[3];
        float color[3];
    };

    static const Vertex vertices[] =
    {
        { { -0.5f, -0.5f, 0.0f }, { 1.0f, 0.0f, 0.0f } },
        { {  0.5f, -0.5f, 0.0f }, { 0.0f, 1.0f, 0.0f } },
        { {  0.0f,  0.5f, 0.0f }, { 0.0f, 0.0f, 1.0f } },
    };

    glGenVertexArrays(1, &s_vao);
    glGenBuffers(1, &s_vbo);
    glBindVertexArray(s_vao);

    glBindBuffer(GL_ARRAY_BUFFER, s_vbo);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex), (void*)offsetof(Vertex, position));
    glEnableVertexAttribArray(0);

    glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex), (void*)offsetof(Vertex, color));
    glEnableVertexAttribArray(1);

    glBindBuffer(GL_ARRAY_BUFFER, 0);
    glBindVertexArray(0);
    write_stage("scene:init:done");
}

static void sceneRender()
{
    glClearColor(0.2f, 0.3f, 0.3f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    glUseProgram(s_program);
    glBindVertexArray(s_vao);
    glDrawArrays(GL_TRIANGLES, 0, 3);
}

static void sceneExit()
{
    write_stage("scene:exit:start");
    glDeleteBuffers(1, &s_vbo);
    glDeleteVertexArrays(1, &s_vao);
    glDeleteProgram(s_program);
    write_stage("scene:exit:done");
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    write_stage("main:entered");
    init_log();

    setMesaConfig();

    if (!initEgl(nwindowGetDefault())) {
        close_log();
        return EXIT_FAILURE;
    }

    write_stage("glad:load:start");
    gladLoadGL();
    write_stage("glad:load:done");

    sceneInit();

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);

    PadState pad;
    padInitializeDefault(&pad);

    write_stage("loop:opengl:start");
    for (int frame = 0; frame < AUTO_FRAMES && appletMainLoop(); frame++) {
        padUpdate(&pad);
        u64 kDown = padGetButtonsDown(&pad);
        if (kDown & HidNpadButton_Plus)
            break;

        sceneRender();
        eglSwapBuffers(s_display, s_surface);
    }
    write_stage("loop:opengl:done");

    sceneExit();
    deinitEgl();

    write_stage("result:ok");
    close_log();
    return EXIT_SUCCESS;
}
