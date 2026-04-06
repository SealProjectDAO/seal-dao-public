# Seal DAO Block Explorer

A lightweight egui-based block explorer for the Seal network.

## Build & Run

```bash
cd apps/seal-explorer
cargo run
```

## Features

- **Overview**: chain height, epoch, state root, crypto info
- **Blocks**: browsable block list with detail view
- **Transactions**: transaction viewer (scaffold)
- **Validators**: validator status table

## Requirements

- Rust 1.75+
- GUI backend (native windowing — works on macOS, Linux, Windows)
- For Wayland/X11 on Linux: `apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev`
