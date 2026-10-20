#pragma once
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
/* Only call with a fixture-owned mkdtemp root after its producers are joined. */
static void sl_fixture_remove_tree(const char *root) {
    DIR *dir = opendir(root);
    assert(dir);
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char path[1024];
        int n = snprintf(path, sizeof(path), "%s/%s", root, entry->d_name);
        struct stat st;
        assert(n > 0 && n < (int)sizeof(path) && !lstat(path, &st));
        if (S_ISDIR(st.st_mode)) sl_fixture_remove_tree(path);
        else assert(!unlink(path));
    }
    assert(!closedir(dir) && !rmdir(root));
}
