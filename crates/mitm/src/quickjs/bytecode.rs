//! Scripts compiled once to QuickJS bytecode, so a run reads the bytecode instead of parsing the
//! source again. Every run still gets its own runtime and context: only the compiled form is
//! shared, never a value.

use std::sync::OnceLock;

use rquickjs::{Ctx, Runtime, Value, qjs};

/// What QuickJS threw while compiling or running, or why it could not start.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct Thrown(String);

impl From<Thrown> for String {
    fn from(thrown: Thrown) -> String {
        thrown.0
    }
}

fn failed(err: impl std::fmt::Display) -> Thrown {
    Thrown(err.to_string())
}

/// The global-script bytecode of `source`, or the compile error.
#[allow(
    unsafe_code,
    reason = "rquickjs 0.14 has no safe call for compiling a script to bytecode"
)]
pub(super) fn compile(source: &str) -> Result<Vec<u8>, Thrown> {
    let text = std::ffi::CString::new(source).map_err(failed)?;
    let runtime = Runtime::new().map_err(failed)?;
    let context = rquickjs::Context::full(&runtime).map_err(failed)?;
    context.with(|ctx| {
        let raw = ctx.as_raw().as_ptr();
        let flags = (qjs::JS_EVAL_TYPE_GLOBAL | qjs::JS_EVAL_FLAG_COMPILE_ONLY) as i32;
        // SAFETY: `text` is NUL-terminated and outlives the call; the result is owned here and
        // freed below, and the buffer QuickJS allocates is copied out before it is freed.
        unsafe {
            let function = qjs::JS_Eval(
                raw,
                text.as_ptr(),
                source.len() as _,
                c"eval_script".as_ptr(),
                flags,
            );
            if qjs::JS_IsException(function) {
                return Err(thrown(&ctx));
            }
            let mut size = 0;
            let buffer =
                qjs::JS_WriteObject(raw, &mut size, function, qjs::JS_WRITE_OBJ_BYTECODE as i32);
            qjs::JS_FreeValue(raw, function);
            if buffer.is_null() {
                return Err(thrown(&ctx));
            }
            let bytes = std::slice::from_raw_parts(buffer, size as usize).to_vec();
            qjs::js_free(raw, buffer.cast());
            Ok(bytes)
        }
    })
}

/// Runs bytecode from [compile] as a global script of `ctx`.
#[allow(
    unsafe_code,
    reason = "rquickjs 0.14 has no safe call for running script bytecode"
)]
pub(super) fn run(ctx: &Ctx<'_>, bytes: &[u8]) -> Result<(), Thrown> {
    let raw = ctx.as_raw().as_ptr();
    // SAFETY: `bytes` came from [compile] in this process, built against the same QuickJS. The
    // function value is consumed by JS_EvalFunction, and its result is handed to a Value that
    // frees it.
    unsafe {
        let function = qjs::JS_ReadObject(
            raw,
            bytes.as_ptr(),
            bytes.len() as _,
            qjs::JS_READ_OBJ_BYTECODE as i32,
        );
        if qjs::JS_IsException(function) {
            return Err(thrown(ctx));
        }
        let result = qjs::JS_EvalFunction(raw, function);
        if qjs::JS_IsException(result) {
            return Err(thrown(ctx));
        }
        drop(Value::from_raw(ctx.clone(), result));
    }
    Ok(())
}

fn thrown(ctx: &Ctx<'_>) -> Thrown {
    let value = ctx.catch();
    Thrown(match value.as_exception() {
        Some(exception) => super::run::describe_exception(exception),
        None => format!("{value:?}"),
    })
}

/// The polyfill and prelude every run evaluates first, with the Quantumult X layer or without.
pub(super) fn prelude(quantumult: bool) -> &'static [u8] {
    static PLAIN: OnceLock<Vec<u8>> = OnceLock::new();
    static QUANTUMULT: OnceLock<Vec<u8>> = OnceLock::new();
    let slot = if quantumult { &QUANTUMULT } else { &PLAIN };
    slot.get_or_init(|| {
        let mut source = format!("{}\n{}", super::run::POLYFILL, super::run::PRELUDE);
        if quantumult {
            source.push('\n');
            source.push_str(super::run::QUANTUMULT);
        }
        compile(&source).unwrap_or_default()
    })
}
