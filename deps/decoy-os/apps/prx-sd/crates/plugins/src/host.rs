//! WASM plugin host backed by wasmtime.
//!
//! When the `wasm-runtime` feature is disabled, [`PluginHost`] is a thin
//! stub that always returns an empty finding list and logs a warning.

use crate::manifest::PluginManifest;
use crate::{PluginFinding, PluginInfo};
use anyhow::{Context, Result};
use std::path::Path;

// ── wasm-runtime enabled ────────────────────────────────────────────────────

#[cfg(feature = "wasm-runtime")]
#[allow(clippy::wildcard_imports, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
mod inner {
    use super::*;
    use wasmtime::*;
    use wasmtime_wasi::WasiCtxBuilder;
    use wasmtime_wasi::p1::WasiP1Ctx;

    /// Per-instance state that host functions read/write.
    struct PluginState {
        wasi: WasiP1Ctx,
        findings: Vec<PluginFinding>,
        file_path: String,
        file_type: String,
        plugin_name: String,
    }

    /// Loads, compiles, and runs a single WASM plugin.
    pub struct PluginHostInner {
        engine: Engine,
        manifest: PluginManifest,
        module: Module,
        info: PluginInfo,
    }

    impl PluginHostInner {
        /// Load a plugin from a directory that contains `plugin.json` and the
        /// referenced `.wasm` file.
        pub fn load(plugin_dir: &Path) -> Result<Self> {
            let manifest_path = plugin_dir.join("plugin.json");
            let manifest = PluginManifest::load(&manifest_path)?;

            // Configure the engine with fuel metering and memory limits.
            let mut config = Config::new();
            config.consume_fuel(true);
            // Clamp memory: 1 page = 64 KiB
            let max_pages = (u64::from(manifest.permissions.max_memory_mb) * 1024 * 1024) / 65536;
            config.memory_reservation(max_pages * 65536);
            let engine = Engine::new(&config).context("failed to create wasmtime engine")?;

            let wasm_path = plugin_dir.join(&manifest.wasm_file);
            let module = Module::from_file(&engine, &wasm_path)
                .with_context(|| format!("failed to compile {}", wasm_path.display()))?;

            // Instantiate once to call on_load / read plugin info.
            let info = Self::init_plugin_info(&engine, &module, &manifest)?;

            Ok(Self {
                engine,
                manifest,
                module,
                info,
            })
        }

        /// Instantiate the module just to call `on_load`, `plugin_name`, and
        /// `plugin_version`.
        fn init_plugin_info(engine: &Engine, module: &Module, manifest: &PluginManifest) -> Result<PluginInfo> {
            let wasi = WasiCtxBuilder::new().build_p1();
            let state = PluginState {
                wasi,
                findings: Vec::new(),
                file_path: String::new(),
                file_type: String::new(),
                plugin_name: manifest.name.clone(),
            };
            let mut store = Store::new(engine, state);
            // Provide generous fuel for init.
            store.set_fuel(1_000_000_000)?;

            let mut linker: Linker<PluginState> = Linker::new(engine);
            wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |s| &mut s.wasi)
                .context("failed to add WASI to linker")?;
            register_host_functions(&mut linker)?;

            let instance = linker
                .instantiate(&mut store, module)
                .context("failed to instantiate module for init")?;

            // Call on_load.
            if let Ok(on_load) = instance.get_typed_func::<(), i32>(&mut store, "on_load") {
                let rc = on_load.call(&mut store, ()).context("on_load call failed")?;
                if rc != 0 {
                    anyhow::bail!("plugin on_load returned non-zero: {rc}");
                }
            }

            // Read plugin_name.
            let name =
                read_plugin_string(&instance, &mut store, "plugin_name").unwrap_or_else(|_| manifest.name.clone());

            // Read plugin_version.
            let version = read_plugin_string(&instance, &mut store, "plugin_version")
                .unwrap_or_else(|_| manifest.version.clone());

            Ok(PluginInfo {
                name,
                version,
                author: manifest.author.clone(),
                description: manifest.description.clone(),
                platforms: manifest.platforms.clone(),
                file_types: manifest.file_types.clone(),
            })
        }

        /// Run the plugin's `scan` export on the supplied file data.
        pub fn scan(&self, file_data: &[u8], file_path: &str, file_type: &str) -> Result<Vec<PluginFinding>> {
            let wasi = WasiCtxBuilder::new().build_p1();

            let state = PluginState {
                wasi,
                findings: Vec::new(),
                file_path: file_path.to_string(),
                file_type: file_type.to_string(),
                plugin_name: self.info.name.clone(),
            };

            let mut store = Store::new(&self.engine, state);

            // Convert max_exec_ms into fuel. Rough heuristic: 1 000 fuel per ms.
            let fuel = self.manifest.permissions.max_exec_ms.saturating_mul(1_000_000);
            store.set_fuel(fuel)?;

            let mut linker: Linker<PluginState> = Linker::new(&self.engine);
            wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |s| &mut s.wasi)
                .context("failed to add WASI to linker (scan)")?;
            register_host_functions(&mut linker)?;

            let instance = linker
                .instantiate(&mut store, &self.module)
                .context("failed to instantiate module for scan")?;

            // Allocate memory inside the guest and copy file_data in.
            let memory = instance
                .get_memory(&mut store, "memory")
                .context("plugin has no exported memory")?;

            // Try to use a plugin-exported allocator; fall back to writing at a
            // fixed offset past the initial data segment.
            let guest_ptr: u32 = if let Ok(alloc) = instance.get_typed_func::<u32, u32>(&mut store, "alloc") {
                alloc
                    .call(&mut store, file_data.len() as u32)
                    .context("plugin alloc failed")?
            } else {
                // Grow memory if necessary and write at the end of the
                // current memory region.
                let current_size = memory.data_size(&store);
                let needed = current_size + file_data.len();
                let pages_needed = (needed as u64)
                    .saturating_sub(memory.data_size(&store) as u64)
                    .div_ceil(65536);
                if pages_needed > 0 {
                    memory
                        .grow(&mut store, pages_needed)
                        .context("failed to grow guest memory")?;
                }
                current_size as u32
            };

            memory
                .write(&mut store, guest_ptr as usize, file_data)
                .context("failed to write file data into guest memory")?;

            // Call scan(ptr, len) -> i32 (threat score).
            let scan_fn = instance
                .get_typed_func::<(u32, u32), i32>(&mut store, "scan")
                .context("plugin does not export scan(i32, i32) -> i32")?;

            let threat_score = match scan_fn.call(&mut store, (guest_ptr, file_data.len() as u32)) {
                Ok(s) => s.clamp(0, 100) as u32,
                Err(e) => {
                    // Out-of-fuel is treated as a timeout; report it but don't
                    // propagate a hard error.
                    tracing::warn!(
                        plugin = %self.info.name,
                        "scan call failed (possible timeout): {e:#}"
                    );
                    0
                }
            };

            let mut findings = std::mem::take(&mut store.data_mut().findings);

            // If the plugin returned a non-zero score but did not call
            // `report_finding`, synthesise a finding from the score alone.
            if threat_score > 0 && findings.is_empty() {
                findings.push(PluginFinding {
                    plugin_name: self.info.name.clone(),
                    threat_name: format!("Plugin.{}", self.info.name),
                    score: threat_score,
                    detail: format!("Plugin '{}' returned threat score {threat_score}", self.info.name),
                });
            }

            Ok(findings)
        }

        pub const fn info(&self) -> &PluginInfo {
            &self.info
        }

        pub const fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
    }

    // ── helper: read a string from a plugin export ──────────────────────────

    fn read_plugin_string(instance: &Instance, store: &mut Store<PluginState>, func_name: &str) -> Result<String> {
        let memory = instance
            .get_memory(&mut *store, "memory")
            .context("no exported memory")?;

        let func = instance
            .get_typed_func::<(u32, u32), u32>(&mut *store, func_name)
            .with_context(|| format!("plugin does not export {func_name}"))?;

        // Provide a 256-byte buffer inside guest memory.
        let buf_size: u32 = 256;
        let current_size = memory.data_size(&*store) as u32;
        let buf_ptr = current_size.saturating_sub(buf_size);
        // Zero the buffer region.
        let zeros = vec![0u8; buf_size as usize];
        memory.write(&mut *store, buf_ptr as usize, &zeros)?;

        let actual_len = func.call(&mut *store, (buf_ptr, buf_size))?;
        let len = (actual_len).min(buf_size) as usize;

        let data = memory.data(&*store);
        let start = buf_ptr as usize;
        let end = start.saturating_add(len).min(data.len());
        let slice = data.get(start..end).unwrap_or_default();
        Ok(String::from_utf8_lossy(slice).into_owned())
    }

    // ── host functions exposed to plugins ───────────────────────────────────

    fn register_host_functions(linker: &mut Linker<PluginState>) -> Result<()> {
        // report_finding(name_ptr, name_len, score, detail_ptr, detail_len)
        linker.func_wrap(
            "env",
            "report_finding",
            |mut caller: Caller<'_, PluginState>,
             name_ptr: u32,
             name_len: u32,
             score: u32,
             detail_ptr: u32,
             detail_len: u32| {
                let Some(Extern::Memory(mem)) = caller.get_export("memory") else {
                    return;
                };
                let data = mem.data(&caller);
                let threat_name = read_guest_string(data, name_ptr, name_len);
                let detail = read_guest_string(data, detail_ptr, detail_len);
                let plugin_name = caller.data().plugin_name.clone();
                caller.data_mut().findings.push(PluginFinding {
                    plugin_name,
                    threat_name,
                    score: score.min(100),
                    detail,
                });
            },
        )?;

        // log_message(level, msg_ptr, msg_len)
        linker.func_wrap(
            "env",
            "log_message",
            |mut caller: Caller<'_, PluginState>, level: u32, msg_ptr: u32, msg_len: u32| {
                let Some(Extern::Memory(mem)) = caller.get_export("memory") else {
                    return;
                };
                let msg = read_guest_string(mem.data(&caller), msg_ptr, msg_len);
                let name = &caller.data().plugin_name;
                match level {
                    0 => tracing::trace!(plugin = %name, "{msg}"),
                    1 => tracing::debug!(plugin = %name, "{msg}"),
                    2 => tracing::info!(plugin = %name, "{msg}"),
                    3 => tracing::warn!(plugin = %name, "{msg}"),
                    _ => tracing::error!(plugin = %name, "{msg}"),
                }
            },
        )?;

        // get_file_path(buf_ptr, buf_len) -> actual_len
        linker.func_wrap(
            "env",
            "get_file_path",
            |mut caller: Caller<'_, PluginState>, buf_ptr: u32, buf_len: u32| -> u32 {
                let path = caller.data().file_path.clone();
                write_to_guest(&mut caller, buf_ptr, buf_len, path.as_bytes())
            },
        )?;

        // get_file_type(buf_ptr, buf_len) -> actual_len
        linker.func_wrap(
            "env",
            "get_file_type",
            |mut caller: Caller<'_, PluginState>, buf_ptr: u32, buf_len: u32| -> u32 {
                let ft = caller.data().file_type.clone();
                write_to_guest(&mut caller, buf_ptr, buf_len, ft.as_bytes())
            },
        )?;

        Ok(())
    }

    fn read_guest_string(data: &[u8], ptr: u32, len: u32) -> String {
        let start = ptr as usize;
        let end = start.saturating_add(len as usize).min(data.len());
        let slice = data.get(start..end).unwrap_or_default();
        String::from_utf8_lossy(slice).into_owned()
    }

    fn write_to_guest(caller: &mut Caller<'_, PluginState>, ptr: u32, len: u32, src: &[u8]) -> u32 {
        let Some(Extern::Memory(mem)) = caller.get_export("memory") else {
            return 0;
        };
        let to_write = src.len().min(len as usize);
        let write_slice = src.get(..to_write).unwrap_or(src);
        if mem.write(&mut *caller, ptr as usize, write_slice).is_err() {
            return 0;
        }
        src.len() as u32
    }
}

// ── wasm-runtime disabled (stub) ────────────────────────────────────────────

#[cfg(not(feature = "wasm-runtime"))]
mod inner {
    use super::*;

    pub struct PluginHostInner {
        manifest: PluginManifest,
        info: PluginInfo,
    }

    impl PluginHostInner {
        pub fn load(plugin_dir: &Path) -> Result<Self> {
            let manifest_path = plugin_dir.join("plugin.json");
            let manifest = PluginManifest::load(&manifest_path)?;
            tracing::warn!(
                plugin = %manifest.name,
                "WASM plugins disabled (compiled without wasm-runtime feature)"
            );
            let info = PluginInfo {
                name: manifest.name.clone(),
                version: manifest.version.clone(),
                author: manifest.author.clone(),
                description: manifest.description.clone(),
                platforms: manifest.platforms.clone(),
                file_types: manifest.file_types.clone(),
            };
            Ok(Self { manifest, info })
        }

        pub fn scan(&self, _file_data: &[u8], _file_path: &str, _file_type: &str) -> Result<Vec<PluginFinding>> {
            tracing::warn!(
                plugin = %self.info.name,
                "WASM plugins disabled; scan is a no-op"
            );
            Ok(Vec::new())
        }

        pub const fn info(&self) -> &PluginInfo {
            &self.info
        }

        pub const fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
    }
}

// ── public wrapper ──────────────────────────────────────────────────────────

/// Host that loads and executes a single WASM plugin.
pub struct PluginHost {
    inner: inner::PluginHostInner,
}

impl PluginHost {
    /// Load a plugin from a directory containing `plugin.json` and its
    /// `.wasm` file.
    pub fn load(plugin_dir: &Path) -> Result<Self> {
        let inner = inner::PluginHostInner::load(plugin_dir)?;
        tracing::info!(
            plugin = %inner.info().name,
            version = %inner.info().version,
            "loaded plugin"
        );
        Ok(Self { inner })
    }

    /// Run the plugin scanner on `file_data`.
    pub fn scan(&self, file_data: &[u8], file_path: &str, file_type: &str) -> Result<Vec<PluginFinding>> {
        self.inner.scan(file_data, file_path, file_type)
    }

    /// Plugin metadata.
    pub const fn info(&self) -> &PluginInfo {
        self.inner.info()
    }

    /// Raw manifest.
    pub const fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }
}
