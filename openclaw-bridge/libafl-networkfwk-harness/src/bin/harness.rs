use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus};
use libafl::events::SimpleEventManager;
use libafl::executors::inprocess::InProcessExecutor;
use libafl::executors::ExitKind;
use libafl::feedbacks::{ConstFeedback, CrashFeedback};
use libafl::fuzzer::{Fuzzer, StdFuzzer};
use libafl::inputs::BytesInput;
use libafl::inputs::HasMutatorBytes;
use libafl::monitors::SimpleMonitor;
use libafl::mutators::havoc_mutations;
use libafl::mutators::scheduled::StdScheduledMutator;
use libafl::schedulers::QueueScheduler;
use libafl::stages::mutational::StdMutationalStage;
use libafl::state::{HasCorpus, StdState};
use libafl_bolts::current_nanos;
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;
use libloading::Library;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

// Template assumptions:
// - You will point this harness at a *publicly exported* parser symbol using TARGET_SYMBOL / --symbol.
// - The parser signature below is a best-effort placeholder. Adjust it to the real signature you discover.
type ParseFn = unsafe extern "C" fn(buf: *const u8, len: usize) -> i32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure any panic produces an immediate process abort (so LLDB stop hooks see it).
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[harness] panic: {info}");
        std::process::abort();
    }));

    let args: Vec<String> = env::args().collect();

    // Replay mode: run once with stdin or a file, then exit.
    // - --stdin
    // - --file /path/to/input.bin
    // Fuzz mode (default): LibAFL loop mutating inputs and calling the parser.
    let replay_stdin = args.iter().any(|a| a == "--stdin");
    let replay_file = value_after(&args, "--file");

    let lib_path = value_after(&args, "--lib")
        .or_else(|| env::var("TARGET_DYLIB_PATH").ok())
        .unwrap_or_else(|| "/System/Library/Frameworks/Network.framework/Network".to_string());

    let symbol = value_after(&args, "--symbol")
        .or_else(|| env::var("TARGET_SYMBOL").ok())
        .unwrap_or_else(|| "decapsulate_frame".to_string());

    // Optional: cap input size (helpful when using stdin/file replay).
    let max_input_bytes: usize = env::var("MAX_INPUT_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256 * 1024);

    // Load the target framework/library and resolve the parser symbol via dlsym.
    let (lib, parser) = load_parser(&lib_path, &symbol)?;

    if replay_stdin || replay_file.is_some() {
        let mut bytes = if replay_stdin {
            read_all_stdin(max_input_bytes)?
        } else {
            let path = replay_file.expect("--file requires a path");
            let mut data = fs::read(path)?;
            if data.len() > max_input_bytes {
                data.truncate(max_input_bytes);
            }
            data
        };

        // Normalize empty inputs to a single 0 byte (some parsers assert non-empty).
        if bytes.is_empty() {
            bytes.push(0);
        }

        unsafe {
            let _ = (parser)(bytes.as_ptr(), bytes.len());
        }

        // Keep the library alive until after the call.
        drop(lib);
        return Ok(());
    }

    // Fuzz mode (LibAFL). This template intentionally prioritizes stability triage (crash discovery),
    // not coverage-guided exploration. Add observers/feedback (e.g., edges map) once you have instrumentation.
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    // Crashes will be written to ./crashes/ as individual files.
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("crashes"))?,
        &mut ConstFeedback::new(false),
        &mut CrashFeedback::new(),
    )?;

    // Seed corpus with a minimal input to mutate.
    if state.corpus().count() == 0 {
        state
            .corpus_mut()
            .add(BytesInput::new(vec![0u8]).into())?;
    }

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, ConstFeedback::new(false), CrashFeedback::new());

    // Keep library alive by moving it into the harness closure environment.
    let mut harness = {
        let _lib = lib;
        move |input: &BytesInput| {
            let bytes = input.bytes();

            // Avoid calling with null pointers.
            if bytes.is_empty() {
                return ExitKind::Ok;
            }

            unsafe {
                let _ = (parser)(bytes.as_ptr(), bytes.len());
            }
            ExitKind::Ok
        }
    };

    // No observers in this template.
    let observers = tuple_list!();

    let mut executor = InProcessExecutor::new(&mut harness, observers, &mut fuzzer, &mut state, &mut mgr)?;

    // Mutational stage: havoc.
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // Optional: stop after N iterations (useful for CI-style “stability check” runs).
    if let Some(iters) = value_after(&args, "--iters").and_then(|v| v.parse::<u64>().ok()) {
        for _ in 0..iters {
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
        }
        return Ok(());
    }

    // Default: fuzz forever.
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}

fn load_parser(lib_path: &str, symbol: &str) -> Result<(Library, ParseFn), Box<dyn std::error::Error>> {
    let lib = unsafe { Library::new(lib_path) }?;

    // libloading expects a nul-terminated symbol name on some platforms. Append \0 defensively.
    let mut sym_name = symbol.as_bytes().to_vec();
    if !sym_name.ends_with(&[0]) {
        sym_name.push(0);
    }

    let parser = unsafe {
        let sym: libloading::Symbol<ParseFn> = lib.get(&sym_name)?;
        *sym
    };

    Ok((lib, parser))
}

fn read_all_stdin(max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut stdin = io::stdin().lock();
    let mut buf = Vec::new();
    stdin.read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        buf.truncate(max_bytes);
    }
    Ok(buf)
}

fn value_after(args: &[String], key: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == key {
            return it.next().cloned();
        }
    }
    None
}

// ASan build notes (macOS):
// - Rust sanitizers require nightly. One common workflow:
//   1) rustup toolchain install nightly
//   2) rustup component add rust-src --toolchain nightly
//   3) RUSTFLAGS="-Zsanitizer=address -C debuginfo=1" \
//      cargo +nightly build -Zbuild-std --target aarch64-apple-darwin
// - ASAN_OPTIONS you may want:
//   ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0
// - If you attach LLDB, consider:
//   (lldb) settings set target.process.stop-on-sharedlibrary-events false
