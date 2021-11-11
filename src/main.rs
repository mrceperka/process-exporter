use clap::{App, Arg};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use lazy_static::lazy_static;
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use regex::Regex;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

#[derive(Debug, Clone)]
struct Range {
    start: u32,
    end: u32,
}
fn validate_range(text: &str) -> Result<Option<Range>, String> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^(\d+)\.\.(\d+)$").unwrap();
    }
    match RE.captures(text) {
        Some(captures) => match (captures.get(1), captures.get(2)) {
            (Some(start), Some(end)) => match (start.as_str().parse(), end.as_str().parse()) {
                (Ok(start), Ok(end)) => {
                    if start > end {
                        return Err(format!(
                            "start of range ({}) must not be greater than the end ({})",
                            start, end
                        ));
                    }
                    let range = Range { start, end };
                    return Ok(Some(range));
                }
                _ => {
                    return Err(format!(
                        "failed to parse start ({}) and end ({})",
                        start.as_str(),
                        end.as_str()
                    ));
                }
            },
            _ => {
                return Err("start and end captures not found".to_string());
            }
        },
        None => return Err("value does not match range regex".to_string()),
    };
}

async fn handler(
    req: Request<Body>,
    shared_sys: &Arc<Mutex<System>>,
    namespace: &String,
    filter_name: &Option<Regex>,
    filter_exe: &Option<Regex>,
    filter_cpu_usage: &Option<Range>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let r = Registry::new();
            let labels = vec!["pid", "uid", "name", "exe"];
            let cpu_usage_gauge = GaugeVec::new(
                    Opts::new("cpu_usage", "CPU usage of given process (in %). It might be bigger than 100 if run on a multicore machine.").namespace(namespace.clone()),
                    &labels,
                ).unwrap();
            let memory_gauge = GaugeVec::new(
                Opts::new("memory", "Memory usage of given process (in KB).")
                    .namespace(namespace.clone()),
                &labels,
            )
            .unwrap();
            let memory_usage_gauge = GaugeVec::new(
                Opts::new(
                    "memory_usage",
                    "Memory usage of given process (in % of total memory).",
                )
                .namespace(namespace.clone()),
                &labels,
            )
            .unwrap();
            r.register(Box::new(cpu_usage_gauge.clone())).unwrap();
            r.register(Box::new(memory_gauge.clone())).unwrap();
            r.register(Box::new(memory_usage_gauge.clone())).unwrap();

            let mut sys = match shared_sys.lock() {
                Ok(v) => v,
                Err(e) => {
                    let mut error_res = Response::new(Body::from(e.to_string()));
                    *error_res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(error_res);
                }
            };

            // not needed with sysinfo 0.21.1
            // sys.refresh_cpu();
            sys.refresh_processes();
            sys.refresh_memory();
            let total_memory = sys.total_memory();
            let processes = sys.processes();
            for (pid, proc) in processes {
                if let Some(filter_name_regex) = filter_name {
                    if filter_name_regex.is_match(proc.name()) == false {
                        continue;
                    }
                }

                let exe_str = proc.exe().to_string_lossy();
                if let Some(filter_exe_regex) = filter_exe {
                    if filter_exe_regex.is_match(&exe_str) == false {
                        continue;
                    }
                }

                let cpu_usage = (100.0 * proc.cpu_usage() as f64).round() / 100.0;
                if let Some(cpu_usage_range) = filter_cpu_usage {
                    let is_in_range = (cpu_usage >= (cpu_usage_range.start as f64))
                        && (cpu_usage <= (cpu_usage_range.end as f64));

                    if false == is_in_range {
                        continue;
                    }
                }

                let pid_str: String = (*pid).to_string();
                let uid_str: String = proc.uid.to_string();
                let label_values = [&pid_str, &uid_str, proc.name(), &exe_str];
                cpu_usage_gauge
                    .with_label_values(&label_values)
                    .set(cpu_usage);
                memory_gauge
                    .with_label_values(&label_values)
                    .set(proc.memory() as f64);
                let mut memory_usage = 0.0;
                if total_memory > 0 {
                    memory_usage = 100.0 * (proc.memory() as f64 / total_memory as f64);
                    memory_usage = (100.0 * memory_usage).round() / 100.0;
                }
                memory_usage_gauge
                    .with_label_values(&label_values)
                    .set(memory_usage);
            }

            // gather
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = r.gather();
            let res = match encoder.encode(&metric_families, &mut buffer) {
                Ok(_) => Response::new(Body::from(buffer)),
                Err(e) => {
                    let mut error_res = Response::new(Body::from(e.to_string()));
                    *error_res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    error_res
                }
            };

            Ok(res)
        }
        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Process exporter")
        .version("0.3.0")
        .about("Prometheus process exporter")
        .arg(
            Arg::with_name("namespace")
                .long("namespace")
                .help("Prometheus namespace. This will prefix metric names.")
                .default_value("r2b2_process")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("socket-address")
                .long("socket-address")
                .help("Socket address for server to bind to.")
                .default_value("0.0.0.0:9333")
                .required(true)
                .validator(|v| match v.parse::<SocketAddr>() {
                    Err(e) => Err(e.to_string()),
                    Ok(_) => Ok(()),
                })
                .takes_value(true),
        )
        .arg(
            Arg::with_name("filter-name")
                .long("filter-name")
                .help("Filter process name by regex")
                .validator(|v| match Regex::new(v.as_str()) {
                    Err(e) => Err(e.to_string()),
                    Ok(_) => Ok(()),
                })
                .takes_value(true),
        )
        .arg(
            Arg::with_name("filter-exe")
                .long("filter-exe")
                .help("Filter process exe by regex")
                .validator(|v| match Regex::new(v.as_str()) {
                    Err(e) => Err(e.to_string()),
                    Ok(_) => Ok(()),
                })
                .takes_value(true),
        )
        .arg(
            Arg::with_name("filter-cpu-usage")
                .long("filter-cpu-usage")
                .help("Filter process usage by expression, e.g., 0..10")
                .validator(|v| match validate_range(v.as_str()) {
                    Err(e) => Err(e.to_string()),
                    Ok(_) => Ok(()),
                })
                .takes_value(true),
        )
        .get_matches();

    let namespace = matches
        .value_of("namespace")
        .expect("expected namespace to be set")
        .to_string();

    let addr: SocketAddr = matches
        .value_of("socket-address")
        .expect("expected socket-address to be set")
        .parse()
        .expect("Expected socket-address to be valid");

    let filter_name = match matches.value_of("filter-name") {
        Some(v) => Some(Regex::new(v).expect("Expected valid regex")),
        None => None,
    };

    let filter_exe = match matches.value_of("filter-exe") {
        Some(v) => Some(Regex::new(v).expect("Expected valid regex")),
        None => None,
    };

    let filter_cpu_usage = match matches.value_of("filter-cpu-usage") {
        Some(v) => match validate_range(v) {
            Ok(range) => range,
            _ => None,
        },
        _ => None,
    };

    let refresh_kind = RefreshKind::new().with_processes().with_memory();
    let mut sys = System::new_with_specifics(refresh_kind);
    sys.refresh_processes();
    sys.refresh_memory();
    let shared_sys = Arc::new(Mutex::new(sys));
    let service = make_service_fn(move |_| {
        let namespace = namespace.clone();
        let filter_name = filter_name.clone();
        let filter_exe = filter_exe.clone();
        let filter_cpu_usage = filter_cpu_usage.clone();
        let shared_sys = shared_sys.clone();
        return async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let namespace = namespace.clone();
                let filter_name = filter_name.clone();
                let filter_exe = filter_exe.clone();
                let filter_cpu_usage = filter_cpu_usage.clone();
                let shared_sys = shared_sys.clone();
                return async move {
                    handler(
                        req,
                        &shared_sys,
                        &namespace,
                        &filter_name,
                        &filter_exe,
                        &filter_cpu_usage,
                    )
                    .await
                };
            }))
        };
    });

    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);

    server.await?;

    Result::Ok(())
}
