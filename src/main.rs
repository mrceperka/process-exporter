use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
extern crate sysinfo;

use sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

fn main() {
    let r = Registry::new();
    let namespace = "r2b2_process";
    let labels = vec!["pid", "name", "exe"];
    let cpu_usage_gauge = GaugeVec::new(
        Opts::new("cpu_usage", "CPU usage of given process (in %). It might be bigger than 100 if run on a multicore machine.").namespace(namespace.clone()),
        &labels,
    )
    .unwrap();
    let memory_gauge = GaugeVec::new(
        Opts::new("memory", "Memory usage of given process (in KB).").namespace(namespace.clone()),
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
    sys.refresh_processes();
    sys.refresh_memory();
    let total_memory = sys.total_memory();
    for (pid, proc) in sys.processes() {
        let pid_str: String = (*pid).to_string();
        let exe_str = proc.exe().to_string_lossy();
        let label_values = [&pid_str, proc.name(), &exe_str];
        cpu_usage_gauge
            .with_label_values(&label_values)
            .set(proc.cpu_usage() as f64);
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

    // Gather the metrics.
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    // Output to the standard output.
    println!("{}", String::from_utf8(buffer).unwrap());
}
