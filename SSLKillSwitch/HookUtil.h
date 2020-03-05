#import <objc/runtime.h>

//
#ifdef __cplusplus
extern "C"
{
#endif
	void HUHookFunction(const char *lib, const char *func, void *hook, void **old);
#ifdef __cplusplus
}
#endif