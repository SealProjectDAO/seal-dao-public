//! Seal DAO Block Explorer — egui-based GUI application.
//!
//! A lightweight block explorer for the Seal network.
//! Connects to a local or remote node and displays:
//! - Chain overview (height, epoch, state root)
//! - Block list with details
//! - Transaction viewer
//! - Validator status
//!
//! # Usage
//!
//! ```bash
//! cd apps/seal-explorer
//! cargo run
//! ```

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
            .with_title("Seal DAO Explorer"),
        ..Default::default()
    };
    eframe::run_native(
        "Seal Explorer",
        options,
        Box::new(|_cc| Ok(Box::new(ExplorerApp::default()))),
    )
}

/// Main application state.
#[derive(Default)]
struct ExplorerApp {
    /// Current view tab.
    current_tab: Tab,
    /// Node RPC URL.
    rpc_url: String,
    /// Whether connected to a node.
    connected: bool,
    /// Chain info.
    chain_height: u64,
    chain_epoch: u64,
    chain_state_root: String,
    /// Mock block list (for scaffold display).
    blocks: Vec<BlockInfo>,
    /// Selected block index.
    selected_block: Option<usize>,
    /// Status message.
    status: String,
}

#[derive(Default, PartialEq)]
enum Tab {
    #[default]
    Overview,
    Blocks,
    Transactions,
    Validators,
}

/// Block summary for display.
struct BlockInfo {
    height: u64,
    epoch: u64,
    tx_count: usize,
    state_root: String,
    proposer: String,
    timestamp: String,
}

impl ExplorerApp {
    fn load_mock_data(&mut self) {
        self.connected = true;
        self.chain_height = 1234;
        self.chain_epoch = 5;
        self.chain_state_root = "a3f8b9c2d1e0...".to_string();
        self.status = "Connected to local devnet".to_string();

        self.blocks = (1..=10)
            .rev()
            .map(|h| BlockInfo {
                height: 1234 - 10 + h,
                epoch: (1234 - 10 + h) / 256,
                tx_count: (h * 3 % 7) as usize,
                state_root: format!("{:016x}...", h * 0x1234567890),
                proposer: format!("seal1val{}...", h % 5 + 1),
                timestamp: format!("2026-04-02 12:{:02}:00", h),
            })
            .collect();
    }
}

impl eframe::App for ExplorerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top panel: navigation tabs
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Seal DAO Explorer");
                ui.separator();
                ui.selectable_value(&mut self.current_tab, Tab::Overview, "Overview");
                ui.selectable_value(&mut self.current_tab, Tab::Blocks, "Blocks");
                ui.selectable_value(&mut self.current_tab, Tab::Transactions, "Transactions");
                ui.selectable_value(&mut self.current_tab, Tab::Validators, "Validators");
            });
        });

        // Bottom panel: status bar
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.connected {
                    ui.label(egui::RichText::new("Connected").color(egui::Color32::GREEN));
                } else {
                    ui.label(egui::RichText::new("Disconnected").color(egui::Color32::RED));
                }
                ui.separator();
                ui.label(&self.status);
            });
        });

        // Central panel: content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                Tab::Overview => self.show_overview(ui),
                Tab::Blocks => self.show_blocks(ui),
                Tab::Transactions => self.show_transactions(ui),
                Tab::Validators => self.show_validators(ui),
            }
        });
    }
}

impl ExplorerApp {
    fn show_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Chain Overview");
        ui.add_space(10.0);

        // Connection
        ui.horizontal(|ui| {
            ui.label("Node URL:");
            ui.text_edit_singleline(&mut self.rpc_url);
            if ui.button("Connect").clicked() {
                self.load_mock_data();
            }
        });
        ui.add_space(10.0);

        if self.connected {
            egui::Grid::new("overview_grid")
                .num_columns(2)
                .spacing([40.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Chain Height:");
                    ui.label(egui::RichText::new(format!("{}", self.chain_height)).strong());
                    ui.end_row();

                    ui.label("Current Epoch:");
                    ui.label(format!("{}", self.chain_epoch));
                    ui.end_row();

                    ui.label("State Root:");
                    ui.label(egui::RichText::new(&self.chain_state_root).monospace());
                    ui.end_row();

                    ui.label("Validators:");
                    ui.label("5 active");
                    ui.end_row();

                    ui.label("Consensus:");
                    ui.label("Algorand-style VRF + Ringtail threshold sigs");
                    ui.end_row();

                    ui.label("Cryptography:");
                    ui.label("ML-DSA-65, ML-KEM-768, SHA3-256 (PQ-secure)");
                    ui.end_row();
                });
        } else {
            ui.label("Enter a node URL and click Connect to start exploring.");
            ui.add_space(5.0);
            ui.label("Or run a local devnet: seal dev --slots 100");
        }
    }

    fn show_blocks(&mut self, ui: &mut egui::Ui) {
        ui.heading("Recent Blocks");
        ui.add_space(10.0);

        if self.blocks.is_empty() {
            ui.label("No blocks loaded. Connect to a node first.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, block) in self.blocks.iter().enumerate() {
                let selected = self.selected_block == Some(i);
                let response = ui.selectable_label(
                    selected,
                    format!(
                        "Block #{} | epoch {} | {} txs | {} | {}",
                        block.height, block.epoch, block.tx_count, block.proposer, block.timestamp
                    ),
                );
                if response.clicked() {
                    self.selected_block = Some(i);
                }
            }
        });

        if let Some(idx) = self.selected_block {
            if let Some(block) = self.blocks.get(idx) {
                ui.add_space(10.0);
                ui.separator();
                ui.heading(format!("Block #{}", block.height));
                egui::Grid::new("block_detail")
                    .num_columns(2)
                    .spacing([40.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Height:");
                        ui.label(format!("{}", block.height));
                        ui.end_row();
                        ui.label("Epoch:");
                        ui.label(format!("{}", block.epoch));
                        ui.end_row();
                        ui.label("Transactions:");
                        ui.label(format!("{}", block.tx_count));
                        ui.end_row();
                        ui.label("State Root:");
                        ui.label(egui::RichText::new(&block.state_root).monospace());
                        ui.end_row();
                        ui.label("Proposer:");
                        ui.label(&block.proposer);
                        ui.end_row();
                    });
            }
        }
    }

    fn show_transactions(&mut self, ui: &mut egui::Ui) {
        ui.heading("Transactions");
        ui.add_space(10.0);
        ui.label("Transaction explorer coming soon.");
        ui.label("Will show: type, sender, payload, signature status, block inclusion.");
    }

    fn show_validators(&mut self, ui: &mut egui::Ui) {
        ui.heading("Validators");
        ui.add_space(10.0);

        if !self.connected {
            ui.label("Connect to a node to see validator status.");
            return;
        }

        egui::Grid::new("validators")
            .num_columns(4)
            .spacing([20.0, 4.0])
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Validator");
                ui.strong("Stake");
                ui.strong("Status");
                ui.strong("Blocks Proposed");
                ui.end_row();

                for i in 1..=5 {
                    ui.label(format!("seal1val{}...", i));
                    ui.label(format!("{},000 SEAL", i * 10));
                    ui.label(egui::RichText::new("Active").color(egui::Color32::GREEN));
                    ui.label(format!("{}", i * 47));
                    ui.end_row();
                }
            });
    }
}
