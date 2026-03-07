use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    success: bool,
    report: Option<String>,
    error: Option<String>,
}

#[tauri::command]
fn greet(name: &str) -> String {
    sentinel_core::greet(name)
}

#[tauri::command]
async fn analyze_process_log(log_path: String) -> Result<AnalysisResult, String> {
    // Get the path to the Python analyzer script
    let mut analyzer_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?
        .parent()
        .ok_or("Failed to get parent directory")?
        .parent()
        .ok_or("Failed to get project root")?
        .parent()
        .ok_or("Failed to get project root")?
        .to_path_buf();
    
    analyzer_path.push("process_analyzer.py");
    
    if !analyzer_path.exists() {
        return Ok(AnalysisResult {
            success: false,
            report: None,
            error: Some("Process analyzer script not found".to_string()),
        });
    }

    // Execute the Python analyzer
    let output = Command::new("python")
        .arg(analyzer_path.to_str().unwrap())
        .arg(&log_path)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                Ok(AnalysisResult {
                    success: true,
                    report: Some(String::from_utf8_lossy(&output.stdout).to_string()),
                    error: None,
                })
            } else {
                Ok(AnalysisResult {
                    success: false,
                    report: None,
                    error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                })
            }
        }
        Err(e) => Ok(AnalysisResult {
            success: false,
            report: None,
            error: Some(format!("Failed to execute analyzer: {}", e)),
        }),
    }
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet, analyze_process_log, select_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
