//! nn-agent-helper: prints the program of each listening socket as JSON.
//!
//! This program runs with CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, so it can
//! read /proc/<pid>/fd and /proc/<pid>/exe of all processes. It has no
//! arguments and reads no input. It only prints data about processes that
//! own listening TCP or unconnected UDP sockets. systemd starts it for each
//! connection on /run/nn-agent-helper.sock (see deploy/nn-agent-helper.socket).

use nn_agent::collector::Ctx;
use nn_agent::collectors::{sockets, sockowner};
use std::collections::HashSet;
use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        eprintln!("usage: nn-agent-helper (no arguments; prints JSON to stdout)");
        return ExitCode::from(2);
    }
    let ctx = Ctx::new("/".into());
    let listening: HashSet<u64> = match sockets::listening(&ctx) {
        Ok(v) => v.into_iter().map(|s| s.inode).collect(),
        Err(e) => {
            eprintln!("nn-agent-helper: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut owners: Vec<sockowner::Owner> = sockowner::fd_owners(&ctx)
        .into_iter()
        .filter(|(inode, _)| listening.contains(inode))
        .map(|(inode, pid)| sockowner::owner_of_pid(&ctx, inode, pid))
        .collect();
    owners.sort_by_key(|o| o.inode);
    let out = serde_json::to_vec(&owners).unwrap_or_else(|_| b"[]".to_vec());
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(&out).and_then(|_| stdout.flush()).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
