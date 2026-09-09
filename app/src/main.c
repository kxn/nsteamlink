#include "platform/application.h"
#include "platform/system.h"
int main(int argc, char **argv) {
    if (!sl_system_preflight())
        return 0;
    return sl_application_run(argc, argv);
}
