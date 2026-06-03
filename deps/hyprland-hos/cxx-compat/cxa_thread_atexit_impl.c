extern int __cxa_atexit(void (*func)(void*), void* obj, void* dso_handle);

int __cxa_thread_atexit_impl(void (*func)(void*), void* obj, void* dso_handle) {
    return __cxa_atexit(func, obj, dso_handle);
}
