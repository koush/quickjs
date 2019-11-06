#ifndef QUICKJS_DEBUGGER_H
#define QUICKJS_DEBUGGER_H

#include "quickjs.h"
#include <time.h>

typedef struct JSDebuggerFunctionInfo {
    // same length as byte_code_buf.
    uint8_t *breakpoints;
    uint32_t dirty;
    int last_line_num;
} JSDebuggerFunctionInfo;

typedef struct JSDebuggerLocation {
    JSAtom filename;
    int line;
    int column;
} JSDebuggerLocation;

typedef struct JSDebuggerInfo {
    JSContext *ctx;
 
    int attempted_connect;
    int peek_ticks;
    void *transport_udata;

    char *message_buffer;
    int message_buffer_length;
    int is_debugging;

    size_t (*transport_read)(void *udata, char* buffer, size_t length);
    size_t (*transport_write)(void *udata, const char* buffer, size_t length);
    size_t (*transport_peek)(void *udata);
    void (*transport_close)(JSContext *ctx, void *udata);

    JSValue breakpoints;
    uint32_t breakpoints_dirty_counter;

    int stepping;
    JSDebuggerLocation step_over;
} JSDebuggerInfo;

void js_debugger_check(JSContext *ctx, JSDebuggerInfo *info);
void js_debugger_free(JSContext *ctx, JSDebuggerInfo *info);

void js_debugger_attach(
    JSContext* ctx,
    size_t (*transport_read)(void *udata, char* buffer, size_t length),
    size_t (*transport_write)(void *udata, const char* buffer, size_t length),
    size_t (*transport_peek)(void *udata),
    void (*transport_close)(JSContext *ctx, void *udata),
    void *udata
);
void js_debugger_connect(JSContext *ctx, char *address);

JSValue js_debugger_file_breakpoints(JSContext *ctx, const char *path);

// requires quickjs internals
JSDebuggerLocation js_debugger_current_location(JSContext *ctx);
JSValue js_debugger_build_backtrace(JSContext *ctx);
int js_debugger_check_breakpoint(JSContext *ctx, uint32_t current_dirty);
JSValue js_debugger_json_stringify(JSContext *ctx, JSValue value);
JSDebuggerInfo *js_debugger_info(JSContext *ctx);
JSValue js_debugger_global_variables(JSContext *ctx);
JSValue js_debugger_local_variables(JSContext *ctx, int stack_index);
JSValue js_debugger_closure_variables(JSContext *ctx, int stack_index);

#endif
