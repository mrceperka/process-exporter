# process-exporter

[![build](https://github.com/mrceperka/process-exporter/actions/workflows/rust.yml/badge.svg)](https://github.com/mrceperka/process-exporter/actions/workflows/rust.yml)

## Usage

```sh
USAGE:
    process-exporter [OPTIONS] --namespace <namespace> --socket-address <socket-address>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --filter-cpu-usage <filter-cpu-usage>    Filter process usage by expression, e.g., 0..10
        --filter-exe <filter-exe>                Filter process exe by regex
        --filter-name <filter-name>              Filter process name by regex
        --namespace <namespace>
            Prometheus namespace. This will prefix metric names. [default: r2b2_process]

        --socket-address <socket-address>        Socket address for server to bind to. [default: 0.0.0.0:9333]
```

# Build

```sh
cargo build --release
```

# Dev

```sh
cargo run
```

Check http://localhost:9333/metrics
