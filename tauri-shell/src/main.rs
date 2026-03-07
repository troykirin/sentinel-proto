use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    success: bool,
    report: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct MemorySnapshot {
    version: String,
    captured_at: String,
    source: SnapshotSource,
    summary: SnapshotSummary,
    watchlist: Vec<SnapshotProcess>,
    processes: Vec<SnapshotProcess>,
    alerts: Vec<SnapshotAlert>,
    notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct SnapshotSource {
    kind: String,
    machine: String,
    environment: String,
    origin: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct SnapshotSummary {
    total_processes: usize,
    total_resident_mb: f64,
    watchlist_count: usize,
    alert_count: usize,
    threshold_mb: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct SnapshotProcess {
    name: String,
    pid: Option<u32>,
    ppid: Option<u32>,
    resident_mb: f64,
    private_mb: Option<f64>,
    cpu_pct: Option<f64>,
    status: String,
    origin: String,
    command: String,
    tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct SnapshotAlert {
    severity: String,
    title: String,
    message: String,
    process: String,
    pid: Option<u32>,
}

impl MemorySnapshot {
    fn normalize(mut self) -> Self {
        if self.summary.total_processes == 0 && !self.processes.is_empty() {
            self.summary.total_processes = self.processes.len();
        }

        if self.summary.total_resident_mb <= 0.0 && !self.processes.is_empty() {
            self.summary.total_resident_mb = self
                .processes
                .iter()
                .map(|process| process.resident_mb)
                .sum();
        }

        if self.summary.watchlist_count == 0 && !self.watchlist.is_empty() {
            self.summary.watchlist_count = self.watchlist.len();
        }

        if self.summary.alert_count == 0 && !self.alerts.is_empty() {
            self.summary.alert_count = self.alerts.len();
        }

        self
    }
}

fn looks_like_repo_root(path: &Path) -> bool {
    path.join("process_analyzer.py").exists() && path.join("ui").join("dist").join("index.html").exists()
}

fn repo_root() -> Result<PathBuf, String> {
    let mut search_roots = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            search_roots.push(parent.to_path_buf());
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        search_roots.push(cwd);
    }

    for search_root in search_roots {
        for candidate in search_root.ancestors() {
            if looks_like_repo_root(candidate) {
                return Ok(candidate.to_path_buf());
            }
        }
    }

    Err("Failed to locate repository root from the current executable or working directory".to_string())
}

fn analyzer_path() -> Result<PathBuf, String> {
    Ok(repo_root()?.join("process_analyzer.py"))
}

fn run_analyzer(log_path: &Path) -> Result<AnalysisResult, String> {
    let repo_root = repo_root()?;
    let analyzer_path = analyzer_path()?;

    if !analyzer_path.exists() {
        return Ok(AnalysisResult {
            success: false,
            report: None,
            error: Some("Process analyzer script not found".to_string()),
        });
    }

    let python_commands = [
        ("python", Vec::<&str>::new()),
        ("py", vec!["-3"]),
        ("python3", Vec::<&str>::new()),
    ];
    let mut execution_errors = Vec::new();

    for (program, args) in python_commands {
        let mut command = Command::new(program);
        command.current_dir(&repo_root);

        for arg in args {
            command.arg(arg);
        }

        let output = command.arg(&analyzer_path).arg(log_path).output();
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                if output.status.success() {
                    return Ok(AnalysisResult {
                        success: true,
                        report: Some(stdout),
                        error: None,
                    });
                }

                return Ok(AnalysisResult {
                    success: false,
                    report: None,
                    error: Some(if stderr.is_empty() {
                        format!("Analyzer exited with status {}", output.status)
                    } else {
                        stderr
                    }),
                });
            }
            Err(error) => {
                execution_errors.push(format!("{}: {}", program, error));
            }
        }
    }

    Ok(AnalysisResult {
        success: false,
        report: None,
        error: Some(format!(
            "Failed to execute analyzer. Tried python, py -3, and python3. {}",
            execution_errors.join(" | ")
        )),
    })
}

fn read_snapshot(path: &Path) -> Result<MemorySnapshot, String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read snapshot file {}: {}", path.display(), e))?;
    serde_json::from_str::<MemorySnapshot>(&contents)
        .map(MemorySnapshot::normalize)
        .map_err(|e| format!("Failed to parse snapshot JSON {}: {}", path.display(), e))
}

#[tauri::command]
fn greet(name: &str) -> String {
    sentinel_core::greet(name)
}

#[tauri::command]
async fn analyze_process_log(log_path: String) -> Result<AnalysisResult, String> {
    run_analyzer(Path::new(&log_path))
}

#[tauri::command]
async fn select_file() -> Result<Option<String>, String> {
    use tauri::api::dialog::blocking::FileDialogBuilder;
    
    let file = FileDialogBuilder::new()
        .add_filter("Log files", &["log", "txt", "csv"])
        .add_filter("All files", &["*"])
        .pick_file();
    
    Ok(file.map(|path| path.to_string_lossy().to_string()))
}

#[tauri::command]
async fn select_snapshot_file() -> Result<Option<String>, String> {
    use tauri::api::dialog::blocking::FileDialogBuilder;

    let file = FileDialogBuilder::new()
        .add_filter("JSON files", &["json"])
        .add_filter("All files", &["*"])
        .pick_file();

    Ok(file.map(|path| path.to_string_lossy().to_string()))
}

#[tauri::command]
async fn load_memory_snapshot(snapshot_path: String) -> Result<MemorySnapshot, String> {
    read_snapshot(Path::new(&snapshot_path))
}

#[tauri::command]
async fn load_example_snapshot() -> Result<MemorySnapshot, String> {
    serde_json::from_str::<MemorySnapshot>(include_str!("../../contracts/memory_snapshot.example.json"))
        .map(MemorySnapshot::normalize)
        .map_err(|e| format!("Failed to parse bundled example snapshot: {}", e))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            greet,
            analyze_process_log,
            select_file,
            select_snapshot_file,
            load_memory_snapshot,
            load_example_snapshot
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
