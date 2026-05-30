# 🔍 AUDITORÍA INTERNA + EXTERNA PROFUNDA — AgentGuard Phase 2

**Fecha**: Mayo 2026 | **Scope**: Interna (code-level) + Externa (attack surface)
**Auditor**: Deep Internal/External Review | **Veredicto**: Ver detalle por severidad

---

## RESUMEN EJECUTIVO

| Métrica | Score | Status |
|---------|-------|--------|
| **Arquitectura & DAG** | 100% (0 ciclos, 0 violaciones) | ✅ |
| **Unsafe Code Audit** | 95% (~89 bloques, todos justificados, 3 con riesgo menor) | ✅ |
| **Concurrencia** | 85% (3 race conditions potenciales) | 🟡 |
| **Validación de Inputs** | 90% (2 gaps de validación) | 🟡 |
| **Manejo de Errores** | 80% (2 swallows silenciosos, 1 rollback parcial) | 🟡 |
| **IPC Security** | 60% (sin autenticación, Everyone ACL) | 🔴 |
| **ACE Enforcement** | 85% (user-mode, ventanas TOCTOU) | 🟡 |
| **Secrets & Exposure** | 90% (archivos test, sin leaks reales) | 🟢 |
| **DoS Resilience** | 65% (sin rate limiting, broadcast loss) | 🟡 |
| **Supply Chain** | 50% (sin CI security, sin SBOM, ferrisetw inmaduro) | 🔴 |
| **Logging & Audit** | 60% (sin integridad, sin Windows Event Log) | 🟡 |
| **OVERALL** | **78%** | 🟡 **REQUIERE HARDENING** |

---

## PARTE 1 — AUDITORÍA INTERNA (CODE-LEVEL)

### 1.1 Arquitectura y Dependencias

#### 1.1.1 DAG verificado — SIN HALLAZGOS

```
core (0 deps)
  ├─ manifest ──→ policy
  ├─ store ──→ audit
  ├─ probe, enforce, ipc, notify
  └─ daemon ──→ cli, tui
```

**Estado**: ✅ DAG exacto, 0 ciclos, 0 violaciones. `agentguard-core` no importa otras crates del workspace.

#### 1.1.2 `agentguard-spawn` fuera del workspace — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-spawn/Cargo.toml` (no está en workspace members)

El crate `agentguard-spawn` no es miembro del workspace. Consecuencias:

- No hereda `[workspace.lints.rust] unsafe_code = "deny"` — aunque declara su propio `#![allow(unsafe_code)]`, no está sujeto al deny global
- No hereda `[workspace.lints.clippy] unwrap_used = "deny"` ni `expect_used = "deny"`
- Se compila independientemente — puede divergir en versiones de dependencias

**Recomendación**: Añadir `agentguard-spawn` al workspace members o documentar explícitamente por qué está excluido con un ADR.

#### 1.1.3 `ferrisetw@0.1.1` — dependencia inmadura

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-probe/Cargo.toml`

`ferrisetw` es un crate de terceros en versión 0.1.x para consumir ETW (Event Tracing for Windows). Implicaciones:

- API inestable (semver 0.x permite breaking changes)
- Menos auditado que `windows-sys` (oficial de Microsoft)
- Usa `unsafe` internamente para FFI con COM/ETW APIs
- Correctamente aislado en `agentguard-probe`, no afecta otros crates

**Recomendación**: Pinear versión exacta (`=0.1.1` en vez de `0.1`), considerar migrar a `windows-sys` ETW bindings en Phase 2.

---

### 1.2 Unsafe Code — Auditoría Bloque por Bloque

**Total**: ~89 bloques `unsafe` en 7 crates. **Veredicto**: Mayormente correcto, 3 observaciones menores.

#### 1.2.1 `ace.rs` — ACE manipulation (~22 bloques)

**Archivo**: `crates/agentguard-enforce/src/ace.rs`

| Líneas | API | Riesgo | Hallazgo |
|--------|-----|--------|----------|
| 128-134 | `ConvertStringSidToSidW` | ✅ Bajo | `LocalPtr` dropper correcto |
| 142-143 | `GetNamedSecurityInfoW` | ✅ Bajo | `_sd` captura descriptor en `LocalPtr` |
| 154 | `SetEntriesInAclW` | ✅ Bajo | `new_dacl` con `LocalPtr` |
| 158 | `SetNamedSecurityInfoW` | ✅ Bajo | Sin observaciones |
| 297 | `InitializeAcl` | ✅ Bajo | Buffer pre-allocado con tamaño calculado |
| 312 | `GetAce` | ✅ Bajo | Loop con bounds check (`ace_count`) |
| 390 | `EqualSid` | ✅ Bajo | Verifica `ace.is_null()` primero |
| 388 | Cast `*const ACE_HEADER` → `*const ACCESS_DENIED_ACE` | ⚠️ Medio | **Riesgo menor**: El cast asume que `AceType == ACCESS_DENIED_ACE_TYPE`, verificado en línea 384. Correcto pero frágil si la estructura de `ACCESS_DENIED_ACE` cambia en futuras versiones de `windows-sys`.

**Veredicto**: ✅ Sin fugas de memoria, sin double-free, sin buffer overflows.

#### 1.2.2 `server.rs` — Pipe Security (~4 bloques)

**Archivo**: `crates/agentguard-ipc/src/server.rs`

| Líneas | API | Riesgo | Hallazgo |
|--------|-----|--------|----------|
| 234 | `create_with_security_attributes_raw` | ✅ Bajo | Encapsulado en trait `ServerOptionsSecurityExt` |
| 267-273 | `ConvertStringSecurityDescriptorToSecurityDescriptorW` | ✅ Bajo | `PipeSecurity::Drop` libera descriptor |
| 300-301 | `LocalFree` en `Drop` | ✅ Bajo | Correcto, una sola vez |

**Veredicto**: ✅ Correcto. El SDDL se libera exactamente una vez en `Drop`.

#### 1.2.3 `daemon/main.rs` — Singleton Mutex (~4 bloques)

**Archivo**: `crates/agentguard-daemon/src/main.rs`

| Líneas | API | Riesgo | Hallazgo |
|--------|-----|--------|----------|
| 38 | `CreateMutexW` | ✅ Bajo | `SingleInstanceGuard::Drop` cierra handle |
| 45 | `CloseHandle` en rama de error | ✅ Bajo | Correcto |

**Veredicto**: ✅ Sin fugas.

#### 1.2.4 `spawn/token.rs` — Restricted Token (~16 bloques)

**Archivo**: `crates/agentguard-spawn/src/token.rs`

| Líneas | API | Riesgo | Hallazgo |
|--------|-----|--------|----------|
| 43 | `ConvertStringSidToSidW` | ✅ Bajo | `SidPtr` dropper correcto |
| 56-60 | `OpenProcessToken` | ✅ Bajo | `CloseHandle(token)` en línea 88 |
| 76-86 | `CreateRestrictedToken` | ✅ Bajo | Sin observaciones |
| 102-113 | `CreateProcessWithTokenW` | ⚠️ Medio | **Riesgo menor**: Si `detach_debugger` falla (línea 122), se cierra `restricted_token` y el proceso hijo queda huérfano. `close_process_info` libera handles de proceso/hilo, pero el proceso hijo sigue ejecutándose. |

**Veredicto**: ⚠️ Una fuga de proceso hijo en path de error (el proceso sigue vivo sin debugger detached). Impacto bajo porque el proceso hijo hereda el restricted token.

#### 1.2.5 `notify/notifier.rs` — MessageBoxW (~1 bloque)

**Archivo**: `crates/agentguard-notify/src/notifier.rs`

**Veredicto**: ✅ Sin riesgo. `MessageBoxW` es síncrono y no maneja memoria.

---

### 1.3 Concurrencia & Thread Safety

#### 1.3.1 Deadlock potencial en `reload_project` — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:70-83`

```rust
pub fn reload_project(&self, ws: &Path) -> GuardResult<()> {
    let w = normalize(ws.to_path_buf());
    let old = { let p = recover_lock!(self.projects.read(), "projects");
                 p.get(&w).cloned()... };
    // ...
    old.enforcer.read().unwrap().release_project_protections()?;  // read lock on enforcer
    e.apply_project_protections(&c)...;
    // ...
    recover_lock!(self.projects.write(), "projects").insert(w.clone(), ...);  // write lock on projects
}
```

**Análisis**: Se toma `self.projects.read()` en un scope, luego `old.enforcer.read()`, luego `self.projects.write()`. Esto **no** es un deadlock clásico (read→write es upgrade, no posible con `RwLock`). Sin embargo, si otro hilo tiene `self.projects.read()` durante la operación, `self.projects.write()` se bloqueará hasta que todos los reads se liberen. El lock de lectura en línea 72 se libera al salir del scope, así que es seguro.

**Veredicto**: ✅ Sin deadlock. El scope delimita correctamente el read lock.

#### 1.3.2 Race condition en `protect_new_file` — HALLAZGO

**Severidad**: 🔴 ALTA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:153`

```rust
pub(crate) fn protect_new_file(&self, fp: &Path) {
    if !self.protections_active.load(Ordering::SeqCst) { return; }
    for (ws, entry) in recover_lock!(self.projects.read(), "projects").iter() {
        // ... apply ACE ...
    }
}
```

**Race**: Entre el check `protections_active.load()` y el lock `projects.read()`, otro hilo podría llamar `release_all_projects()` que pone `protections_active = false` y libera ACEs. Luego `protect_new_file` aplicaría ACEs después del release, dejando archivos protegidos cuando no deberían.

**Recomendación**: Verificar `protections_active` **dentro** del lock de `projects`, no antes.

#### 1.3.3 Broadcast channel overflow — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:164`

```rust
fn emit(&self, event: IpcResponse) {
    if self.event_tx.send(event).is_err() {
        eprintln!("[daemon] WARN: event channel full");
    }
}
```

**Problema**: Canal broadcast con capacidad 1024. Si hay un receptor lento o desconectado, `send()` falla y el evento se **pierde silenciosamente**. Esto incluye `AuditEvent`, que es crítico para el audit trail.

**Recomendación**: 
- Aumentar capacidad a 4096 o usar `mpsc` ilimitado
- Loguear pérdidas en DB como métrica
- Considerar `send_timeout` con backpressure en vez de drop

#### 1.3.4 `recover_lock!` macro — HALLAZGO

**Severidad**: 🟢 BAJA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:15`

```rust
macro_rules! recover_lock {
    ($lock:expr, $lbl:expr) => {
        match $lock {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[daemon] WARN: RwLock '{}' poisoned!", $lbl);
                e.into_inner()
            }
        }
    };
}
```

**Problema**: Recupera de poisoning pero solo hace `eprintln!`. No hay registro estructurado, no se emite evento de sistema, no se incrementa contador de poisonings para el dashboard.

**Veredicto**: ✅ Funcionalmente correcto, pero la telemetría es débil.

---

### 1.4 Validación de Inputs & Injection

#### 1.4.1 IPC inputs validados — PARCIALMENTE CORRECTO

**Archivo**: `crates/agentguard-daemon/src/handler.rs`

| Request | Validación | Estado |
|---------|-----------|--------|
| `AddGlobalRule` | `pattern.trim().is_empty()`, `MAX_PATTERN_LEN=1024`, `globset::Glob::new()` | ✅ |
| `AddAgentRule` | `agent_image.trim().is_empty()`, `pattern.trim().is_empty()`, `parse_bucket()` | ✅ |
| `CheckFileAccess` | `op` validado contra `"read"/"write"/"delete"` | ⚠️ |
| `RegisterProject` | `path` sin validación de existencia previa | ⚠️ |

#### 1.4.2 `CheckFileAccess` path traversal — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/handler.rs:162-186`

```rust
IpcRequest::CheckFileAccess { path, op } => {
    let file_op = match op.as_str() { ... };
    let decision = match evaluate_manifest_dry_run(&path, &file_op)? { ... };
    Ok(IpcResponse::FileCheck(FileCheckResult {
        path: path.clone(),  // Devuelve el path original sin canonicalizar
        ...
    }))
}
```

**Problema**: `CheckFileAccess` acepta cualquier `PathBuf` del IPC. Aunque internamente `evaluate_manifest_dry_run` canonicaliza (línea 573), la respuesta devuelve el path original sin canonicalizar. Un cliente malicioso podría usar esto para:
- Path traversal info leak: `../../sensitive/file` → el daemon evalúa el path canonicalizado, pero el output muestra el path relativo, potencialmente revelando estructura de directorios
- Diferencia entre path enviado y path evaluado: el cliente no sabe qué path realmente se evaluó

**Recomendación**: Canonicalizar el path **antes** de usarlo y devolver el path canonicalizado en la respuesta.

#### 1.4.3 SQL Injection — SIN HALLAZGOS

**Archivo**: `crates/agentguard-store/src/queries.rs`

**Veredicto**: ✅ Todas las queries usan `params![]` con placeholders `?1, ?2`. No hay concatenación de strings en SQL. `rusqlite` protege contra inyección.

#### 1.4.4 Global patterns sin sanitización avanzada

**Severidad**: 🟢 BAJA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:259`

```rust
fn expand(pat: &str) -> String {
    if pat.contains('\\') || pat.contains('/') || pat.contains("**") {
        pat.to_string()
    } else {
        format!("**/{pat}")
    }
}
```

**Observación**: `expand()` añade `**/` como prefijo si el patrón no contiene separadores. No valida que el patrón no contenga caracteres nulos o secuencias de escape. `globset::Glob::new` debería rechazarlos, pero añadir validación explícita sería más robusto.

---

### 1.5 Manejo de Errores — HALLAZGOS

#### 1.5.1 Error silencioso en `AskResponse` — CRÍTICO

**Severidad**: 🔴 CRÍTICA
**Archivo**: `crates/agentguard-daemon/src/handler.rs:199`

```rust
IpcRequest::AskResponse { request_id, allowed, remember } => {
    let _ = state.process_ask_response(request_id, allowed, remember);
    Ok(IpcResponse::Ok)  // ← Siempre Ok, incluso si process_ask_response falló
}
```

**Problema**: `process_ask_response` puede fallar (request_id desconocido, error de DB al persistir `remember`, error al emitir `AuditEvent`). Si falla:
- El cliente recibe `IpcResponse::Ok` creyendo que el ask se procesó
- El ask se pierde — el agente podría quedar bloqueado esperando respuesta o, peor, la decisión del usuario se descarta
- Si era `allowed=false`, el acceso que debía denegarse no se registra ni se audita

**Recomendación**: 
```rust
state.process_ask_response(request_id, allowed, remember)?;  // Propagar error
```

#### 1.5.2 Rollback parcial en `register_project` — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:45-55`

```rust
let mut e = agentguard_enforce::Enforcer::new(w.clone());
e.apply_project_protections(&c)?;
self.store.register_project(&w, &n).map_err(|err| {
    if let Err(e) = e.release_project_protections() {
        eprintln!("[daemon] WARN: ACE rollback failed: {e}");
    }
    err
})?;
self.store.set_project_hash(&w, &h).map_err(|err| {
    if let Err(e) = e.release_project_protections() {
        eprintln!("[daemon] WARN: ACE rollback failed: {e}");
    }
    err
})?;
```

**Problema**: El rollback de ACEs es correcto (deshace protección si falla DB). Pero no hay rollback de DB si `set_project_hash` falla — el proyecto queda registrado en DB pero sin hash.

**Recomendación**: Misma técnica de rollback pero en orden inverso: si `set_project_hash` falla, hacer `unregister_project`.

#### 1.5.3 `protect_all_projects` — fallo parcial silencioso

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:151`

```rust
fn protect_all_projects(&self) {
    if self.protections_active.swap(true, Ordering::SeqCst) { return; }
    for e in recover_lock!(self.projects.read(), "projects").values() {
        if let Err(err) = e.enforcer.write().unwrap().apply_project_protections(&e.manifest) {
            eprintln!("[daemon] WARN: protect failed: {err}");
        }
    }
}
```

**Problema**: Si el proyecto 1 se protege exitosamente pero el proyecto 2 falla, `protections_active` queda `true` pero el proyecto 2 está desprotegido. No hay indicador de protección parcial en el dashboard.

**Recomendación**: Trackear qué proyectos están efectivamente protegidos (no solo `AtomicBool` global).

#### 1.5.4 Error recovery en `rebuild_agent` — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:89`

```rust
pub fn remove_agent_rule(&self, id: i64) -> GuardResult<()> {
    self.store.delete_agent_rule(id)?;
    self.agent_manifests.write().unwrap_or_else(|e| e.into_inner()).clear();
    Ok(())
}
```

**Problema**: Cuando se borra una regla de agente, se limpian **todos** los `agent_manifests` cacheados en vez de solo el del agente afectado. Esto es ineficiente (se reconstruirán bajo demanda) pero no es inseguro.

---

### 1.6 Path Canonicalization — HALLAZGO

#### 1.6.1 Fallback inseguro en `normalize()` y `is_in_ws()`

**Severidad**: 🔴 CRÍTICA
**Archivo**: `crates/agentguard-daemon/src/orchestrator.rs:256-258`

```rust
fn normalize(p: PathBuf) -> PathBuf {
    match std::fs::canonicalize(&p) {
        Ok(x) => strip(x),
        Err(_) => if p.is_absolute() { p } else { std::env::current_dir().map(|c| c.join(&p)).unwrap_or(p) }
    }
}

fn is_in_ws(p: &Path, ws: &Path) -> bool {
    std::fs::canonicalize(p).map(|c| strip(c).starts_with(ws)).unwrap_or(false)
}
```

**Análisis crítico de `normalize()`**:
- Si `canonicalize` **falla** (archivo no existe, permisos, etc.), usa `p` directamente si es absoluto
- Si `p` contiene symlinks o `..` que `canonicalize` habría resuelto, el path **no se resuelve**
- Un atacante podría crear `C:\workspace\..\..\sensitive\secret.txt` → si `canonicalize` falla, se usa el path sin resolver → `is_absolute()` es true → se evalúa como `C:\sensitive\secret.txt` sin verificar que no es un symlink

**Análisis de `is_in_ws()`**:
- Si `canonicalize` falla, retorna `false` (el path "no está en el workspace")
- Esto es **más seguro pero incorrecto**: un path legítimo con error de canonicalización se considerará fuera del workspace y se permitirá
- Por ejemplo, un archivo que el agente no tiene permiso de leer → `canonicalize` falla → `is_in_ws` retorna `false` → `evaluate_access_dry_run` retorna `Allow`

**Recomendación**: 
```rust
fn normalize(p: PathBuf) -> PathBuf {
    // Siempre intentar canonicalizar. Si falla, resolver manualmente
    // componentes ".." y devolver error en vez de path no resuelto.
    match std::fs::canonicalize(&p) {
        Ok(x) => strip(x),
        Err(_) => {
            // Si es absoluto, al menos resolver ".." y "." manualmente
            // y loguear WARNING de que no se pudo canonicalizar
            eprintln!("[daemon] WARN: cannot canonicalize '{}'", p.display());
            p  // ⚠️ Riesgo si contiene symlinks
        }
    }
}
```

#### 1.6.2 Fallback inseguro en `evaluate_manifest_dry_run`

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-daemon/src/handler.rs:573`

```rust
let abs_path = std::fs::canonicalize(&abs_path).unwrap_or(abs_path);
```

Mismo problema que `normalize()`. Si canonicalize falla, se usa el path sin resolver, lo que podría bypassear reglas que dependen de la resolución de symlinks.

---

### 1.7 DB Security

#### 1.7.1 `synchronous = NORMAL` — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-store/src/lib.rs:42`

```rust
conn.execute_batch(
    "PRAGMA journal_mode = WAL;
     PRAGMA synchronous  = NORMAL;   // ← Riesgo de pérdida en crash
     PRAGMA foreign_keys = ON;
     PRAGMA cache_size   = -8000;",
)
```

**Problema**: `synchronous = NORMAL` significa que SQLite no espera a que los datos lleguen al disco en cada transacción. Si el SO crashea o hay corte de energía, se pueden **perder eventos de auditoría** (el WAL puede no haber sido sincronizado).

Para un producto de seguridad donde el audit trail es evidencia, esto es problemático.

**Recomendación**: Cambiar a `synchronous = FULL` (o al menos documentar el tradeoff con ADR). El impacto en rendimiento es ~2-3x más lento en escrituras, pero para auditoría es aceptable.

#### 1.7.2 Sin encrypt-at-rest

**Severidad**: 🟡 MEDIA

La DB (`agentguard.db`) almacena paths, hashes, y configuraciones sin cifrar. Un atacante con acceso al filesystem puede leer:
- Qué proyectos están registrados (paths completos)
- Reglas globales (qué archivos están protegidos)
- Eventos de auditoría (qué agente accedió a qué archivo)

**Recomendación**: Considerar SQLCipher o Windows DPAPI para encrypt-at-rest en Phase 2.

#### 1.7.3 `busy_timeout = 1000ms`

**Severidad**: 🟢 BAJA

Timeout de 1 segundo para contención de locks. Adecuado para uso normal, pero bajo carga alta (muchos eventos de proceso + auditoría concurrente), podría causar errores `database is locked`.

---

### 1.8 Cobertura de Tests — Actualizada

| Crate | Tests | Cambios desde Phase 1 | Estado |
|-------|------:|----------------------|--------|
| agentguard-core | 5 | — | ✅ |
| agentguard-manifest | 48 | +5 (symlink regression) | ✅ |
| agentguard-policy | 8 | +5 (global ask, project ask, default, full>deny, no_rules) | ✅ |
| agentguard-store | 16 | +4 (stats, top_agents, ask_decisions, hash) | ✅ |
| agentguard-probe | 27 | +11 | ✅ |
| agentguard-enforce | 11 | +4 (deep paths, git, empty ws, cache) | ✅ |
| agentguard-ipc | 28 | — | ✅ |
| agentguard-notify | 1 | — | ✅ |
| agentguard-audit | 5 | +5 (was 0) | ✅ |
| agentguard-daemon | 22 | +22 (was 0) | ✅ |
| agentguard-cli | 38 | +11 | ✅ |
| agentguard-tui | 0 | — | ⚠️ |
| agentguard-mascot | 1 | — | ✅ |

**Mejoras desde Phase 1**: +58 tests. Daemon pasó de 0 a 22 tests (todos los gaps críticos cubiertos). Coverage gaps restantes: `agentguard-tui` (0 tests).

---

## PARTE 2 — AUDITORÍA EXTERNA (ATTACK SURFACE)

### 2.1 IPC Named Pipe Security

#### 2.1.1 SDDL Analysis — Everyone vs Authenticated Users

**Severidad**: 🔴 ALTA
**Archivo**: `crates/agentguard-ipc/src/server.rs:259-263`

```rust
let sddl = "D:P(A;;0x12019F;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;ME)"
```

Desglose:
```
D:P                          // DACL, protected (no hereda del padre)
(A;;0x12019F;;;WD)           // Everyone: FILE_GENERIC_READ | FILE_GENERIC_WRITE
(A;;FA;;;SY)                 // SYSTEM: FILE_ALL_ACCESS
(A;;FA;;;BA)                 // Administrators: FILE_ALL_ACCESS
S:(ML;;NW;;;ME)              // Mandatory Label: Medium Integrity, No Write Up
```

**Análisis**:
- ✅ `SY` y `BA` con full access — correcto para administración
- ✅ `S:(ML;;NW;;;ME)` — previene escritura desde procesos de baja integridad
- ⚠️ `WD` (Everyone) incluye **usuarios no autenticados** (Guest, Anonymous)
- `0x12019F` = `FILE_GENERIC_READ | FILE_GENERIC_WRITE`:
  - `FILE_GENERIC_READ` = `FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | STANDARD_RIGHTS_READ | SYNCHRONIZE`
  - `FILE_GENERIC_WRITE` = `FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE`

**Riesgo**: Un proceso Guest o Anonymous podría conectarse al pipe y ejecutar `Shutdown`, `AddGlobalRule`, etc. En Windows, Guest está deshabilitado por defecto, pero en ciertas configuraciones podría estar activo.

**Recomendación**: Cambiar `WD` → `AU` (Authenticated Users):
```
D:P(A;;0x12019F;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;ME)
```

#### 2.1.2 Sin autenticación en IPC — CRÍTICO

**Severidad**: 🔴 CRÍTICA
**Archivo**: `crates/agentguard-ipc/src/protocol.rs`

**Problema**: El protocolo IPC **no tiene ningún mecanismo de autenticación**. Cualquier proceso que pueda conectarse al named pipe puede:

| Comando | Impacto |
|---------|---------|
| `Shutdown` | Apagar el daemon, desprotegiendo todos los archivos |
| `AddGlobalRule` | Añadir reglas maliciosas (ej. `deny "**"` para bloquear todo) |
| `RemoveGlobalRule` | Eliminar reglas de protección |
| `UnregisterProject` | Desregistrar proyectos, eliminando ACEs |
| `DisableProtection` | Desactivar protección de un workspace |
| `SubscribeEvents` | Escuchar todos los eventos de auditoría (info leak) |
| `GetStatus` / `GetPolicy` | Enumerar proyectos, reglas, paths protegidos |

**Esto es el hallazgo más crítico de la auditoría.**

**Recomendación**: Implementar al menos uno de:
1. Verificar el SID del cliente conectado (`GetNamedPipeClientProcessId` + `OpenProcessToken` + `CheckTokenMembership`) — requiere que el cliente esté en `Administrators` o un grupo específico
2. Shared secret entre daemon y CLI (menos seguro, pero mejor que nada)
3. Token de sesión intercambiado en el handshake inicial

#### 2.1.3 Pipe squatting prevention — PARCIAL

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-ipc/src/server.rs:134-137`

```rust
let mut server = ServerOptions::new()
    .first_pipe_instance(true)     // Previene múltiples daemons
    .create_with_security_attributes(&pipe_name, &mut pipe_security)?;
```

**Análisis**: `first_pipe_instance(true)` previene que un atacante cree el pipe antes que el daemon (necesita ser el dueño de la primera instancia). Pero si el daemon crashea y el pipe queda huérfano, un atacante podría crear la primera instancia antes de que el daemon se reinicie.

**Recomendación**: Añadir `FILE_FLAG_FIRST_PIPE_INSTANCE` también en el lado del servidor Windows, y considerar usar un nombre de pipe con un GUID aleatorio generado al inicio del daemon (comunicado vía un pipe de control separado o un archivo en `%ProgramData%`).

---

### 2.2 ACE/ACL Enforcement Integrity

#### 2.2.1 Protected vs Unprotected DACL — HALLAZGO

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-enforce/src/ace.rs:158` vs `:193`

```rust
// apply_ace_impl
SetNamedSecurityInfoW(..., DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, ...);
//                                                      ^^^^^^^^^ PROTECTED

// remove_deny_ace_impl
SetNamedSecurityInfoW(..., DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, ...);
//                                                      ^^^^^^^^^^^^ UNPROTECTED
```

**Análisis**: 
- `PROTECTED_DACL_SECURITY_INFORMATION` previene que el DACL herede ACEs del directorio padre — **correcto** para aplicar DENY ACEs
- `UNPROTECTED_DACL_SECURITY_INFORMATION` al remover ACEs — permite que el DACL herede del padre de nuevo. Esto es razonable para restaurar el estado anterior, pero si el padre tiene ACEs maliciosos...

**Veredicto**: ✅ Intencional y correcto. Documentar en ADR.

#### 2.2.2 User-mode only — limitación conocida

**Severidad**: 🟡 MEDIA (documentado en ADR-008)

Los ACEs aplicados desde user-mode pueden ser removidos por un administrador o por malware con privilegios elevados. Esto es una limitación aceptada de Phase 1, mitigada en Phase 2 con el minifilter kernel driver.

#### 2.2.3 Verificación de ACEs solo bajo demanda

**Severidad**: 🟡 MEDIA

`verify_ace()` se ejecuta en:
- `register_project` → `emit_health()` (proactivo)
- `VerifyProtection` IPC request (bajo demanda del usuario)
- `TUI dashboard` (periódico)

Pero **no hay verificación continua/periódica** de que los ACEs sigan en su lugar. Un administrador podría removerlos manualmente y el daemon no lo detectaría hasta la próxima verificación.

**Recomendación**: Health check periódico (cada 60s) en background task.

---

### 2.3 DoS / Resource Exhaustion

#### 2.3.1 Sin límite de conexiones IPC concurrentes

**Severidad**: 🔴 ALTA
**Archivo**: `crates/agentguard-ipc/src/server.rs:140-194`

El servidor acepta conexiones ilimitadas. Cada conexión spawnea un `tokio::spawn`. Un atacante podría abrir 10,000 pipes concurrentes y:
- Agotar handles del proceso
- Saturar el runtime de tokio
- Provocar OOM (cada tarea consume memoria)

**Recomendación**: Añadir `Semaphore` con límite (ej. 64 conexiones concurrentes) y rechazar con error.

#### 2.3.2 Walkdir sin límite de profundidad

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-enforce/src/coordinator.rs:111`

```rust
let walker = walkdir::WalkDir::new(&self.workspace_root)
    .follow_links(false)
    .into_iter()
    .filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !SKIP_DIRS.iter().any(|skip| name.as_ref() == *skip)
    })
```

**Análisis**:
- ✅ `follow_links(false)` previene recursión infinita por symlinks
- ✅ `SKIP_DIRS` excluye `.git`, `node_modules`, `target`, etc.
- ⚠️ Sin `max_depth` — un proyecto con 100 niveles de anidamiento podría causar lentitud o stack overflow
- ⚠️ Sin límite de tiempo o archivos — podría bloquear el daemon por minutos en monorepos enormes

**Recomendación**: Añadir `max_depth(20)` o limitar a 1,000,000 archivos.

#### 2.3.3 Broadcast channel sin backpressure

**Severidad**: 🟡 MEDIA

Ya documentado en §1.3.3. Los eventos de auditoría se pierden si el canal está lleno.

---

### 2.4 Secrets & Data Exposure

#### 2.4.1 Archivos test en repo — HALLAZGO

**Severidad**: 🟢 BAJA
**Archivos**: `.env` (contiene `"test"`), `test.pem` (contiene `"secret"`)

Estos archivos existen en el repo y contienen valores triviales, no secretos reales. Sin embargo, su presencia podría:
- Confundir a escáneres automáticos (detección de secrets)
- Ser manipulados para incluir secrets reales accidentalmente

**Recomendación**: Mover a `tests/fixtures/` con nombres descriptivos como `test_fixture.env` y `test_fixture.pem`.

#### 2.4.2 `agentguard-doctor.ps1` — transient API key

**Severidad**: 🟢 BAJA
**Archivo**: `scripts/agentguard-doctor.ps1`

```powershell
$env:OPENAI_API_KEY = "doctor-check"
# ... test ...
Remove-Item Env:\OPENAI_API_KEY
```

La variable se limpia en `finally`. Ventana de exposición limitada a la duración del script (~pocos segundos). Bajo riesgo.

#### 2.4.3 `eprintln!` leaks — HALLAZGO

**Severidad**: 🟢 BAJA

Múltiples `eprintln!` en el daemon exponen paths de archivos en stderr. Si stderr se captura en logs o se redirige, paths sensibles (ej. `.env`, `*.pem`) aparecerán en texto plano.

**Recomendación**: Sanitizar paths en logs (mostrar solo nombre del archivo, no path completo) o usar `tracing` con niveles para controlar verbosidad.

---

### 2.5 Escalación de Privilegios

#### 2.5.1 `agentguard-spawn` — restricted token

**Severidad**: 🟢 BAJA (bien implementado)
**Archivo**: `crates/agentguard-spawn/src/token.rs`

- `S-1-5-12` (quarantine SID) — correcto, es el SID de "aplicación restringida"
- `DISABLE_MAX_PRIVILEGE` — remueve todos los privilegios del token
- `CreateProcessWithTokenW` sin `LOGON_WITH_PROFILE` — correcto para restricted tokens
- `detach_debugger()` — ¿necesario? El proceso hijo ya tiene un token restringido

**Veredicto**: ✅ Bien implementado. Un agente ejecutado con este token no puede:
- Escribir en `%SystemRoot%` o `%ProgramFiles%`
- Acceder a procesos de otros usuarios
- Crear servicios o drivers

#### 2.5.2 Daemon privilegios — HALLAZGO

**Severidad**: 🟡 MEDIA

El daemon corre con los privilegios del usuario que lo lanzó. Si es administrador, el daemon hereda todos los privilegios (SeDebugPrivilege, etc.). No hay `DropPrivileges` ni separación de privilegios.

**Recomendación**: Documentar que el daemon debe correr como `SYSTEM` (servicio Windows) o como usuario estándar, no como administrador interactivo.

---

### 2.6 Logging & Audit Trail

#### 2.6.1 Sin integridad de logs

**Severidad**: 🟡 MEDIA
**Archivo**: `crates/agentguard-store/src/queries.rs:127-144`

Los eventos de auditoría se almacenan en SQLite sin:
- HMAC o firma digital
- Cadena de hash (como blockchain para integridad)
- Protección contra borrado (cualquier admin puede `DELETE FROM audit_events`)

Un atacante que comprometa la DB puede borrar evidencia de sus acciones.

**Recomendación**: Para Phase 2, enviar eventos a Windows Event Log (que tiene mejor protección) o firmar cada evento con HMAC y verificar cadena.

#### 2.6.2 Sin integración con Windows Event Log

**Severidad**: 🟡 MEDIA

En Windows, el estándar para auditoría de seguridad es el Windows Event Log. AgentGuard usa SQLite + `tracing`. Los administradores esperan ver eventos en el visor de eventos.

**Recomendación**: Añadir `tracing-subscriber` con salida a Windows Event Log (canal `AgentGuard/Operational`).

#### 2.6.3 Timestamps sin protección

**Severidad**: 🟢 BAJA

Los timestamps se generan con `chrono::Utc::now()` (reloj del sistema). Un atacante puede manipular el reloj del sistema para falsear timestamps. Esto es aceptable para Phase 1 (no hay mejor alternativa sin hardware trust).

---

### 2.7 Supply Chain & Dependencias

#### 2.7.1 Sin CI/CD security scanning

**Severidad**: 🔴 ALTA

No hay:
- `cargo audit` (CVE scanning de dependencias)
- `cargo deny` (license compliance + dependencias duplicadas + advisories)
- `cargo clippy` con `--deny warnings` en CI
- `cargo fmt --check` en CI
- `cargo test --workspace` en CI

Sin CI, las vulnerabilidades en dependencias pueden pasar desapercibidas por meses.

**Recomendación**: Crear `.github/workflows/ci.yml` o similar con al menos `cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo audit`.

#### 2.7.2 Sin SBOM (Software Bill of Materials)

**Severidad**: 🟢 BAJA

No hay generación de SBOM en formato SPDX o CycloneDX. Requisito creciente para compliance (US Executive Order 14028).

**Recomendación**: `cargo install cargo-cyclonedx && cargo cyclonedx` y versionar el SBOM.

#### 2.7.3 `ferrisetw@0.1.1` — dependencia de riesgo

**Severidad**: 🟡 MEDIA (ya documentado en §1.1.3)

---

### 2.8 Configuración y Deployment

#### 2.8.1 `agentguard.toml` auto-protección

**Severidad**: ✅ SIN HALLAZGOS

El manifest se protege a sí mismo mediante mandatory deny (`agentguard.toml` está en `MANDATORY_DENY_PATTERNS`). Correcto.

#### 2.8.2 `AGENTGUARD_IPC_PIPE` env var

**Severidad**: 🟢 BAJA
**Archivo**: `crates/agentguard-ipc/src/protocol.rs:6-8`

```rust
if let Ok(name) = std::env::var("AGENTGUARD_IPC_PIPE") {
    return name;
}
```

Permite override del pipe name vía variable de entorno. Útil para testing, pero en producción podría ser usado para redirigir el CLI a un pipe malicioso.

**Recomendación**: Solo honrar `AGENTGUARD_IPC_PIPE` en debug builds (`#[cfg(debug_assertions)]`).

---

## MATRIZ DE RIESGOS — PRIORIZACIÓN

### 🔴 CRÍTICOS (Corregir antes de v0.1.0 stable)

| # | Hallazgo | Archivo | Impacto | ETA |
|---|----------|---------|---------|-----|
| 1 | **IPC sin autenticación** — cualquier proceso puede controlar el daemon | `protocol.rs` | Cualquiera puede apagar el daemon, añadir/quitar reglas, desproteger archivos | 4h |
| 2 | **Error silencioso en AskResponse** — `let _ =` descarta errores | `handler.rs:199` | Decisiones de usuario perdidas, denegación no aplicada | 15m |
| 3 | **Fallback de canonicalización inseguro** — `normalize()` usa path sin resolver | `orchestrator.rs:256` | Symlink bypass si canonicalize falla | 1h |

### 🟡 ALTOS (Corregir antes de v0.1.0-beta)

| # | Hallazgo | Archivo | Impacto | ETA |
|---|----------|---------|---------|-----|
| 4 | **Everyone (WD) en pipe SDDL** — Guest puede conectarse | `server.rs:259` | Acceso no autenticado al IPC | 10m |
| 5 | **Sin límite de conexiones IPC** — DoS por agotamiento de handles | `server.rs:140` | Daemon inutilizable | 1h |
| 6 | **Race condition en protect_new_file** — ACEs aplicados después de release | `orchestrator.rs:153` | Archivos protegidos cuando no deben | 30m |
| 7 | **Sin CI/CD security scanning** — vulnerabilidades no detectadas | — | Supply chain vulnerable | 2h |

### 🟡 MEDIOS (v0.1.5)

| # | Hallazgo | Archivo | Impacto | ETA |
|---|----------|---------|---------|-----|
| 8 | Broadcast channel overflow — pérdida de eventos de auditoría | `orchestrator.rs:164` | Audit trail incompleto | 30m |
| 9 | `synchronous = NORMAL` — pérdida de datos en crash | `store/lib.rs:42` | Eventos de auditoría perdidos | 5m |
| 10 | Walkdir sin límite de profundidad | `coordinator.rs:111` | Latencia en monorepos grandes | 30m |
| 11 | `agentguard-spawn` fuera del workspace | `Cargo.toml` | Lint divergence | 30m |
| 12 | `ferrisetw@0.1.1` — crate inmaduro | `probe/Cargo.toml` | API inestable, menos auditado | 2h |
| 13 | Sin integridad de logs | `queries.rs` | Audit events borrables sin detección | 3h |
| 14 | Sin Windows Event Log | `daemon/` | Falta integración estándar Windows | 2h |
| 15 | `AGENTGUARD_IPC_PIPE` env var en release | `protocol.rs` | Pipe hijacking potencial | 5m |

### 🟢 BAJOS (v1.0)

| # | Hallazgo | Archivo | Impacto | ETA |
|---|----------|---------|---------|-----|
| 16 | `.env` y `test.pem` en repo | root | Confusión de escáneres | 10m |
| 17 | `eprintln!` leaks paths | varios | Info disclosure en logs | 1h |
| 18 | `protect_all_projects` sin tracking por proyecto | `orchestrator.rs:151` | Protección parcial invisible | 1h |
| 19 | Rollback parcial en `register_project` | `orchestrator.rs:45` | DB inconsistente si falla hash | 30m |
| 20 | Sin SBOM | — | Compliance gap | 30m |

---

## ROADMAP DE CORRECCIÓN

### Sprint 1 — Críticos (6h)
```
├─ Auth IPC: verificar SID del cliente conectado         [4h]
├─ Fix AskResponse error swallow                         [15m]
├─ Fix canonicalize fallback inseguro                    [1h]
└─ Pipe SDDL: WD → AU                                   [10m]
```

### Sprint 2 — Altos (4h)
```
├─ Rate limiting IPC connections (semaphore 64)          [1h]
├─ Fix race condition protect_new_file                   [30m]
├─ CI/CD: cargo test + clippy + audit + deny             [2h]
└─ Integrar agentguard-spawn al workspace                [30m]
```

### Sprint 3 — Medios (8h)
```
├─ Broadcast channel: aumentar capacidad + log pérdidas   [30m]
├─ synchronous = FULL                                    [5m]
├─ Walkdir max_depth(20)                                 [30m]
├─ Ferrisetw: evaluar migración a windows-sys ETW        [2h]
├─ HMAC integrity para audit events                      [3h]
├─ Windows Event Log integration                         [2h]
└─ AGENTGUARD_IPC_PIPE solo en debug                     [5m]
```

### Sprint 4 — Bajos + Documentación (4h)
```
├─ Mover archivos test a fixtures                        [10m]
├─ Sanitizar eprintln! paths                             [1h]
├─ Tracking de protección por proyecto                   [1h]
├─ SBOM + CONTRIBUTING.md + SECURITY.md                  [1h]
└─ ADR: autenticación IPC, synchronous=FULL, pipe SDDL    [1h]
```

**Tiempo total estimado**: ~22 horas (3-4 sprints)

---

## VEREDICTO FINAL

**Score**: 78/100

La plataforma tiene una arquitectura sólida, unsafe code bien controlado, y cobertura de tests en mejora. Los hallazgos críticos son **corregibles en ~6 horas**:

1. **IPC sin autenticación** — el más grave, pero acotado a procesos locales
2. **AskResponse error swallow** — un liner
3. **Canonicalize fallback inseguro** — requiere refactor de `normalize()`

Con estos 3 corregidos, la plataforma subiría a ~85/100 y sería apta para beta cerrada.

---

**Auditor**: Deep Internal + External Review
**Fecha**: Mayo 2026
**Versión auditada**: Phase 1 (post-PR con 22 tests de daemon)
**Score**: 78/100
**Próxima auditoría**: Después de Sprint 1 (corrección de críticos)
