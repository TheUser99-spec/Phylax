<div align="center">

![Stars](https://img.shields.io/github/stars/TheUser99-spec/Phylax?style=for-the-badge&color=f2c94c)
![Version](https://img.shields.io/github/v/release/TheUser99-spec/Phylax?style=for-the-badge&color=6cdda3)
![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows)
<br>
[![X](https://img.shields.io/badge/X-@Phylaxdev-000000?style=for-the-badge&logo=x)](https://x.com/Phylaxdev)

[English](README.md) &nbsp;|&nbsp; [Español](README.es.md)

</div>

<br>

## ⭐ Phylax — Protección a nivel de SO para agentes de IA

**Una capa de seguridad para Windows que aplica ACLs reales para que el kernel bloquee a los agentes de IA antes de que toquen archivos protegidos.**

- Bloquea lecturas a `.env`, claves, secretos mediante DENY ACEs
- Bloquea eliminaciones de `migrations/`, config, infra mediante etiquetas MIC
- Compatible con Claude Code, Cursor, Windsurf, Aider, OpenCode, Copilot
- Dashboard web en `http://127.0.0.1:1977` + TUI de terminal (ratatui, 60fps)
- Reportes de compliance: EU AI Act, NIST, ISO 42001, SOC 2
- Gobernanza de servidores MCP + detección de exfiltración de datos (DEX)
- Fase 1: refuerzo mediante ACLs en modo usuario. Fase 2: driver kernel minifilter (en desarrollo)
- Open source (Apache 2.0). 100% local. Buscando revisión técnica.

> **Se agradece feedback técnico y revisión de seguridad.**<br>
> ¿Encontraste una limitación? Abre un issue. ¿Quieres auditar el código? `cargo build --workspace`.

<p align="center">
  <img src="assets/demo.gif" alt="Phylax Demo" width="720">
</p>

---

## Qué es Phylax

**Phylax es una barrera de seguridad para agentes de IA.** Garantiza que los agentes puedan editar tu código fuente — pero jamás tocar tus secretos, configuraciones o archivos del sistema.

Por debajo, aplica ACLs reales de Windows para que el propio kernel del SO devuelva `ACCESS_DENIED` antes de que el agente toque un solo byte del archivo protegido. Claude Code, Cursor, OpenCode, Copilot, Windsurf, Aider — no importa qué agente sea. Si el kernel dice que no, el agente no ve nada.

---

## Por qué existe

Los agentes de IA tienen acceso sin restricciones al sistema de archivos. Pueden leer secretos, borrar migraciones o destrozar archivos de configuración — sin preguntar.

**Ejemplos reales:**

```
Claude intentó borrar migrations/ → BLOQUEADO
Cursor intentó leer .env            → BLOQUEADO
OpenCode intentó modificar secrets/ → BLOQUEADO
```

Hay miles de issues abiertos en Claude Code, Cursor, Copilot y otras herramientas documentando agentes que destruyen datos silenciosamente. No porque sean maliciosos — sino porque no entienden el contexto, el valor ni las consecuencias.

Phylax traza una frontera. El agente puede editar tu código fuente. Jamás podrá tocar tu `.env`, tus claves SSH ni tus archivos de política.

---

## Instalación

> **Inspecciona el instalador primero:** [`install.ps1`](https://raw.githubusercontent.com/TheUser99-spec/Phylax/main/install.ps1)

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/Phylax/main/install.ps1 | iex
phylax init
phylax run
```

<details>
<summary>Instalación manual (compilar desde el código)</summary>

```bash
git clone https://github.com/TheUser99-spec/Phylax.git
cd Phylax
cargo build --workspace --release
```
</details>

---

## ¿Para quién es esto?

- **Vibe coders** que usan Claude, Cursor, Windsurf o cualquier herramienta de IA
- **Desarrolladores** que trabajan con agentes que alucinan operaciones de archivos
- **Cualquiera** con `.env`, API keys, configuraciones o archivos de infraestructura
- **Equipos** que quieren la productividad de un agente sin el riesgo
- **Gente que ya perdió datos** por un agente de IA y no quiere que vuelva a pasar

---

## Por qué Phylax es diferente

| Esto no es | Esto sí es |
|---|---|
| No es un linter | **Refuerzo a nivel de kernel** |
| No es un sandbox | **ACLs reales de Windows + etiquetas MIC** |
| No es un plugin | **Funciona con todos los agentes, sin integración** |
| No es una regla de prompt | **El SO bloquea la E/S — el agente no puede evitarlo** |
| Sin dependencia de la nube | **100% local, cero telemetría** |

---

## Cómo funciona

1. **Detecta** — Phylax identifica procesos de agentes de IA por nombre, variables de entorno e inspección de línea de comandos
2. **Clasifica** — Cada operación de E/S se compara contra tus reglas en `phylax.toml`
3. **Refuerza** — Los archivos coincidentes reciben DENY ACEs + etiquetas Mandatory Integrity Control. El kernel de Windows bloquea el acceso en ring 3
4. **Audita** — Cada intento bloqueado se registra en SQLite local

---

## 🛡️ Anti-bypass (3 capas de protección)

Incluso si un agente intenta modificar las ACLs o tomar posesión del archivo, Phylax lo bloquea a nivel de sistema operativo.

| Capa | Mecanismo | Bloquea |
|---|---|---|
| 1 | DENY ACE → Everyone → GENERIC_ALL | Lectura, escritura, eliminación |
| 2 | DENY ACE → Everyone → WRITE_DAC, WRITE_OWNER, DELETE | Modificación de ACLs, cambio de propietario |
| 3 | Etiqueta MIC → High Integrity + NO_WRITE_UP | `icacls /remove:d` y escalado de privilegios |

La capa 3 es el golpe de gracia: incluso si un agente ejecuta `icacls /remove:d` para eliminar el DENY ACE, falla porque el agente corre con integridad Medium mientras que el archivo está etiquetado como High Integrity con NO_WRITE_UP. El kernel rechaza la escritura sin importar quién sea el propietario.

---

## Modelo de permisos

Seis niveles ordenados por prioridad. **Deny siempre gana.**

| Prioridad | Nivel | Significado |
|---|---|---|
| 1 | `[deny]` | Bloqueo total |
| 2 | `[ask]` | El usuario debe aprobar |
| 3 | `[full]` | Sin restricciones |
| 4 | `[delete]` | Leer + Eliminar |
| 5 | `[write]` | Leer + Escribir |
| 6 | `[read]` | Solo lectura |

Cuando no hay regla que coincida: lectura permitida, escritura pregunta, eliminación denegada.

[Documentación completa del modelo de permisos →](https://phylax.pages.dev/docs#permission-model)

---

## phylax.toml

```toml
[project]
name = "mi-proyecto"
default = "conservative"

[deny]
files = [".env", ".env.*", "secrets/**", "*.pem", "*.key"]

[ask]
files = ["Cargo.lock", "migrations/**"]

[write]
files = ["src/**", "tests/**"]

[read]
files = ["README.md", "docs/**"]
```

---

## Comandos

| Comando | Qué hace |
|---|---|
| `phylax start` | Inicia daemon + abre dashboard web |
| `phylax init` | Crea phylax.toml, inicia el daemon, registra el proyecto |
| `phylax run` | Inicia daemon + TUI de terminal (60fps) |
| `phylax stop` | Detiene el daemon (libera los bloqueos de archivos) |
| `phylax status` | Estado en vivo: proyectos, agentes, eventos, bloqueos |
| `phylax project validate` | Valida la sintaxis de phylax.toml |
| `phylax project check -f <f> -o <op>` | Simulación de acceso a archivo |
| `phylax project check -f <f> -o <op> -a <agent>` | Simulación por agente específico |
| `phylax project verify` | Auditoría de cobertura de protección |
| `phylax global add deny "*.env"` | Agrega una regla global de denegación |
| `phylax agent add opencode deny "*.pem"` | Agrega regla por agente |
| `phylax compliance status` | EU AI Act / NIST / ISO 42001 / SOC 2 |
| `phylax mcp discover` | Descubre servidores MCP en el sistema |
| `phylax dex` | Verifica riesgo de exfiltración de datos |
| `phylax scan` | Escanea archivos de modelos IA maliciosos |
| `phylax audit list` | Ver historial de auditoría |
| `phylax audit export` | Exportar logs (csv, json, ocsf, cef) |
| `phylax audit verify-integrity` | Verificar integridad del hash-chain |
| `phylax update` | Auto-actualización desde GitHub |

---

## Compilar desde el código fuente

```bash
git clone https://github.com/TheUser99-spec/Phylax.git
cd Phylax
cargo build --workspace --release
```

---

## Hoja de ruta

- [x] Detección de procesos y clasificación de agentes de IA
- [x] Parser de phylax.toml con motor de políticas basado en globs
- [x] Refuerzo mediante ACLs/ACEs de Windows
- [x] Triple capa anti-bypass (DENY ACEs + etiquetas MIC)
- [x] Registro de auditoría en SQLite
- [x] Protocolo IPC (30+ tipos de solicitud)
- [x] Dashboard de terminal (ratatui, 60fps) + Dashboard web
- [x] CLI unificada con comandos compliance, MCP, DEX, scanner
- [x] Daemon invisible
- [x] Reportes EU AI Act / NIST / ISO 42001 / SOC 2
- [x] Descubrimiento y gobernanza de servidores MCP
- [x] Detección de exfiltración de datos (DEX)
- [x] Escáner de archivos de modelos IA (pickle, safetensors, gguf)
- [x] Verificación de integridad del hash-chain de auditoría
- [x] Landing page + FAQ + tutorial + docs bilingües
- [ ] Driver kernel minifilter (Fase 2)
- [ ] Bloqueo solo para agentes (sin necesidad de detener el daemon)
- [ ] Multiplataforma (macOS/Linux)

---

## Documentación

| Documento | Tema |
|---|---|
| [Quickstart](docs/quickstart.md) | Guía completa |
| [Architecture](docs/01-architecture.md) | Diseño del sistema |
| [Core types](docs/02-core-types.md) | Modelo de permisos |
| [Manifest & policy](docs/03-manifest-policy.md) | phylax.toml |
| [Storage & audit](docs/04-storage-audit.md) | Esquema SQLite |
| [Detection](docs/05-detection-enforcement.md) | Clasificación de procesos |
| [IPC & daemon/CLI](docs/06-ipc-daemon-cli.md) | Protocolo + ciclo de vida |
| [ADR index](docs/adr/README.md) | Decisiones de arquitectura |
| [Landing page](https://phylax.pages.dev) | Sitio completo del producto |
| [Tutorial](https://phylax.pages.dev/tutorial) | Guía de 5 minutos |
| [Kit para creadores](TUTORIAL-KIT.md) | Scripts de video para YouTubers |
| [Kit de prensa](PRESS-KIT.md) | Logos, colores, assets de marca |
| [Currículum](CURRICULUM.md) | Curso completo (35 lecciones) |

---

## Comunidad

- ⭐ [GitHub](https://github.com/TheUser99-spec/Phylax) — estrellas, issues, contribuciones
- 🐦 [X / Twitter](https://x.com/Phylaxdev) — actualizaciones, anuncios
- 📖 [Documentación](https://phylax.pages.dev/docs) — referencia completa
- 🎓 [Tutorial](https://phylax.pages.dev/tutorial) — empieza en 5 minutos
- 🎬 [Kit para creadores](TUTORIAL-KIT.md) — haz un video sobre Phylax

---

## Licencia

Phylax es open-source bajo la **Licencia Apache 2.0**. Ver [LICENSE](LICENSE).

Se distribuye **sin garantía**. Ver [DISCLAIMER.md](DISCLAIMER.md).

---

<br>

<div align="center">

**Si Phylax salvó tu `.env` hoy, ya sabes qué hacer →**

[![Stars](https://img.shields.io/github/stars/TheUser99-spec/Phylax?style=social)](https://github.com/TheUser99-spec/Phylax)
&nbsp;
[![X](https://img.shields.io/badge/X-@Phylaxdev-000000?style=social&logo=x)](https://x.com/Phylaxdev)

<sub>Construido con Rust — Windows-first, a prueba de agentes.</sub>

</div>
