#ifndef POR_LIB_H
#define POR_LIB_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int LoadDB(const char* path);
const char* UserInfo(uint64_t id);
#ifdef __cplusplus
}
#endif

#endif