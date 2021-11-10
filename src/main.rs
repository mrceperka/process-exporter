use clap::{App, Arg};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use std::error::Error;
use std::net::SocketAddr;

use sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

async fn handler(req: Request<Body>, namespace: &String) -> Result<Response<Body>, hyper::Error> {
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

            let refresh_kind = RefreshKind::new().with_processes().with_memory();
            let mut sys = System::new_with_specifics(refresh_kind);
            sys.refresh_cpu();
            sys.refresh_memory();
            sys.refresh_processes();
            let total_memory = sys.total_memory();
            for (pid, proc) in sys.processes() {
                /*
                if proc.name() != "stress" {
                    continue;
                }
                */
                let pid_str: String = (*pid).to_string();
                let uid_str: String = proc.uid.to_string();
                let exe_str = proc.exe().to_string_lossy();
                let label_values = [&pid_str, &uid_str, proc.name(), &exe_str];

                let cpu_usage = (100.0 * proc.cpu_usage() as f64).round() / 100.0;
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
        .version("0.1.0")
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

    let service = make_service_fn(move |_| {
        let namespace = namespace.clone();
        return async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let namespace = namespace.clone();
                return async move { handler(req, &namespace).await };
            }))
        };
    });

    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);

    server.await?;

    Result::Ok(())
}
