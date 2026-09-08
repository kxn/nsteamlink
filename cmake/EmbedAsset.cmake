file(READ "${INPUT}" data HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," data "${data}")
file(WRITE "${OUTPUT}" "#include <stddef.h>\nconst unsigned char nsl_background[] = {${data}};\nconst size_t nsl_background_size = sizeof(nsl_background);\n")
