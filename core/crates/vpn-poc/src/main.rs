//! Proof of concept: one HTTP(S) request through a WireGuard profile, without
//! root, a TUN device or route changes.
//!
//!   vpn-poc --conf surfshark-de.conf https://api.ipify.org
//!   vpn-poc --conf client1.conf --ca-file lab-ca.pem -i https://secret.vpn.test/

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use vpn_core::{request, Profile, RequestSpec, Settings};

const USAGE: &str =
    "usage: vpn-poc --conf FILE [--conf FILE ...] [-X METHOD] [-H 'Name: value'] [-d BODY]
               [--ca-file PEM] [--insecure] [--allow-private] [--timeout SECS]
               [--connect-timeout SECS] [--max-redirects N] [--repeat N] [-i] URL";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("vpn-poc: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let mut confs = Vec::new();
    let mut spec = RequestSpec::default();
    let mut include = false;
    let mut repeat = 1u32;
    let mut url = None;

    let secs = |v: Option<String>| -> Result<Duration, String> {
        let v = v.ok_or("missing value")?;
        v.parse::<f64>()
            .ok()
            .filter(|s| *s > 0.0)
            .map(Duration::from_secs_f64)
            .ok_or_else(|| format!("invalid number of seconds `{v}`"))
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--conf" => confs.push(PathBuf::from(args.next().ok_or("--conf needs a file")?)),
            "-X" | "--method" => spec.method = args.next().ok_or("-X needs a method")?,
            "-H" | "--header" => {
                let h = args.next().ok_or("-H needs a header")?;
                let (n, v) = h.split_once(':').ok_or("headers look like `Name: value`")?;
                spec.headers
                    .push((n.trim().into(), v.trim().as_bytes().to_vec()));
            }
            "-d" | "--data" => spec.body = args.next().ok_or("-d needs a body")?.into_bytes(),
            "--ca-file" => spec.ca_file = Some(args.next().ok_or("--ca-file needs a file")?.into()),
            "--insecure" => spec.verify_tls = false,
            "--allow-private" => spec.allow_private = true,
            "--timeout" => spec.timeout = secs(args.next())?,
            "--connect-timeout" => spec.connect_timeout = secs(args.next())?,
            "--max-redirects" => {
                spec.max_redirects = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--max-redirects needs a number")?
            }
            "--repeat" => {
                repeat = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n > 0)
                    .ok_or("--repeat needs a positive number")?
            }
            "-i" | "--include" => include = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}\n{USAGE}")),
            _ => url = Some(arg),
        }
    }
    spec.url = url.ok_or(USAGE)?;
    if confs.is_empty() {
        return Err(USAGE.into());
    }
    let profiles = confs
        .iter()
        .map(|c| Profile::from_file(c, false))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let profile = if profiles.len() == 1 {
        profiles.into_iter().next().unwrap()
    } else {
        Profile::pool(&profiles).map_err(|e| e.to_string())?
    };
    let settings = Settings::default();

    let mut failed = false;
    for n in 1..=repeat {
        let started = Instant::now();
        match request(&profile, &spec, &settings) {
            Ok(resp) => {
                if include || repeat > 1 {
                    eprintln!(
                        "[{n}] HTTP {} from {} via {} in {:.0} ms ({} bytes, {} redirects)",
                        resp.status,
                        resp.remote_ip,
                        resp.effective_url,
                        started.elapsed().as_secs_f64() * 1000.0,
                        resp.body.len(),
                        resp.redirects
                    );
                }
                if include {
                    for (name, value) in &resp.headers {
                        eprintln!("{name}: {}", String::from_utf8_lossy(value));
                    }
                    eprintln!();
                }
                std::io::stdout()
                    .write_all(&resp.body)
                    .map_err(|e| e.to_string())?;
                if repeat > 1 {
                    println!();
                }
            }
            Err(e) => {
                eprintln!(
                    "[{n}] {:?} error after {:.0} ms: {e}",
                    e.kind(),
                    started.elapsed().as_secs_f64() * 1000.0
                );
                failed = true;
            }
        }
    }
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
