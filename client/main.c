#include "platform/application.h"
/* Runs the same runtime and cleanup as the product; no private UI or input path. */
int main(int argc, char **argv) {
    if (argc > 1)
        return sl_application_run(argc, argv);
    char *args[] = {"switch-stream-selftest", "--frames", "600", 0};
    return sl_application_run(3, args);
}
