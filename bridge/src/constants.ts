export const MAX_JSON_BYTES = 1024 * 1024
export const MAX_ARTIFACT_RESPONSE_BYTES = 2 * 1024 * 1024
export const MAX_MCP_RESPONSE_BYTES = 2 * 1024 * 1024
export const MAX_UPLOAD_BYTES = 524_288_000
export const MAX_CHILD_RESPONSE_BYTES = 64 * 1024

export const REQUIRED_TOOL_NAMES = Object.freeze([
  'analysis_case_checkpoint',
  'analysis_context_pack',
  'artifact_read',
  'sample_delete',
  'workflow_run',
  'workflow_search',
])

export const BUSINESS_TOOL_NAMES = Object.freeze([
  'workflow_run',
  'artifact_read',
  'analysis_case_checkpoint',
  'analysis_context_pack',
  'sample_delete',
])

export const ACTIVATION_TARGETS = Object.freeze([
  'analysis.case.checkpoint',
  'analysis.context.pack',
  'sample.delete',
])

export const STATIC_WORKFLOW_STAGES = Object.freeze([
  'fast_profile',
  'enrich_static',
  'function_map',
])

export const STATIC_PLUGINS = Object.freeze(
  'android,android-package,angr,api-hash,apk-smali,apple-container,apple-objc-swift,apple-signing,batch,binary-diff,binary-hardening,btf,bytecode,capstone,code-analysis,compiler-codegen,container-analysis,cpp-abi-layout,crackme,cross-module,cuda-binary,culifter,deep-unpack,die,dotnet-decompile,dotnet-managed,dotnet-reactor,ebpf-bytecode,elf-macho,external-re-bridge,firmware,ghidra,go-analysis,graphviz,gtirb,host-correlation,javascript-deobfuscation,jsimplifier,jsir-cascade,jsvmp-analysis,jvm,jvm-decompile,kb-collaboration,kernel-driver-surface,lib-identify,lief,linux-binary,linux-package,llvm-bitcode,malware,managed-il-xrefs,manifold,memory-forensics,metadata,miasm,ml-model,native-debug-types,native-object,observability,office-analysis,pcap-analysis,pdf-analysis,pe-analysis,pe-signature,python-decompile,qbdi,radare2,remill,reporting,restringer,retdec,revng,rizin,rust-binary,sbom,serialization-format,shader-ir,similarity,static-triage,strings,syscall-abi-surface,tee-enclave,threat-intel,triton,uefi-smm-surface,unity-managed,unpacking,upx,visualization,vm-analysis,vuln-scanner,wabt,wasm,wasm-component,windows-debug-symbols,windows-installer,windows-interface-surface,yara,yara-x,zig-binary'.split(
    ','
  )
)

export const CHILD_ENV_BASE: Readonly<Record<string, string>> = Object.freeze({
  NODE_ENV: 'production',
  PYTHONUNBUFFERED: '1',
  RIKUNE_DOCKER_PROFILE: 'static',
  RIKUNE_BACKEND_PROFILE: 'default',
  NODE_ROLE: 'analyzer',
  PATH: '/opt/java/openjdk/bin:/opt/rizin/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  JAVA_HOME: '/opt/java/openjdk',
  HOME: '/tmp/rikune-home',
  XDG_CONFIG_HOME: '/tmp/rikune-home/.config',
  XDG_CACHE_HOME: '/tmp/rikune-home/.cache',
  LOG_LEVEL: 'info',
  WORKSPACE_ROOT: '/data/workspaces',
  API_STORAGE_ROOT: '/data/storage',
  DB_PATH: '/data/state/database.db',
  CACHE_ROOT: '/data/cache',
  AUDIT_LOG_PATH: '/data/audit/audit.log',
  GHIDRA_INSTALL_DIR: '/opt/ghidra',
  GHIDRA_PROJECT_ROOT: '/data/workspaces/.ghidra-projects',
  GHIDRA_LOG_ROOT: '/data/audit/ghidra',
  RIZIN_PATH: '/opt/rizin/bin/rizin',
  SANDBOX_PYTHON_PATH: '/usr/local/bin/python3',
  JADX_PATH: '/opt/jadx/bin/jadx',
  ANGR_PYTHON: '/opt/angr-venv/bin/python',
  APKTOOL_PATH: '/usr/bin/apktool',
  DIE_PATH: '/usr/bin/diec',
  ILSPYCMD_PATH: '/usr/local/bin/ilspycmd',
  BINWALK_PATH: '/usr/bin/binwalk',
  GORESYM_PATH: '/usr/local/bin/GoReSym',
  GRAPHVIZ_DOT_PATH: '/usr/bin/dot',
  JSIMPLIFIER_WORKER_PATH: '/opt/rikune-backends/jsimplifier/bin/jsimplifier-worker.js',
  CAPA_RULES_PATH: '/opt/capa-rules',
  MANIFOLD_WORKER_PATH: '/opt/rikune-backends/manifold/bin/manifold-worker.js',
  VOLATILITY3_PATH: '/usr/local/bin/vol',
  VOL3_SYMBOL_PATH: '/opt/vol3-symbols',
  EXIFTOOL_PATH: '/usr/bin/exiftool',
  TSHARK_PATH: '/usr/bin/tshark',
  OSSLSIGNCODE_PATH: '/usr/bin/osslsigncode',
  RESTRINGER_PATH: '/opt/rikune-backends/restringer/bin/restringer-worker.js',
  RETDEC_PATH: '/opt/retdec/bin/retdec-decompiler',
  RETDEC_INSTALL_DIR: '/opt/retdec',
  UPX_PATH: '/usr/local/bin/upx',
  WABT_PATH: '/opt/wabt/bin',
  CAPA_PATH: '/usr/local/bin/capa',
  API_MAX_TOTAL_BYTES: '107374182400',
  API_MAX_FILE_SIZE: '536870912',
  API_ENABLED: 'true',
  API_PORT: '18080',
  SURFACE_PROGRESSIVE: '1',
  SURFACE_AUTO_ACTIVATE_TIER0: '0',
  RUNTIME_MODE: 'disabled',
  STATIC_WORKFLOW_STAGES: STATIC_WORKFLOW_STAGES.join(','),
  PLUGINS: STATIC_PLUGINS.join(','),
})

export type RouteSpec = {
  readonly tool: (typeof BUSINESS_TOOL_NAMES)[number]
  readonly waiterMs: number
  readonly hardMs: number
  readonly mutation: boolean
  readonly responseLimit: number
}

export const ROUTES: Readonly<Record<string, RouteSpec>> = Object.freeze({
  '/internal/v1/workflows/start': {
    tool: 'workflow_run',
    waiterMs: 120_000,
    hardMs: 300_000,
    mutation: true,
    responseLimit: MAX_MCP_RESPONSE_BYTES,
  },
  '/internal/v1/workflows/promote': {
    tool: 'workflow_run',
    waiterMs: 30_000,
    hardMs: 300_000,
    mutation: true,
    responseLimit: MAX_MCP_RESPONSE_BYTES,
  },
  '/internal/v1/workflows/status': {
    tool: 'workflow_run',
    waiterMs: 15_000,
    hardMs: 15_000,
    mutation: false,
    responseLimit: MAX_MCP_RESPONSE_BYTES,
  },
  '/internal/v1/artifacts/read': {
    tool: 'artifact_read',
    waiterMs: 30_000,
    hardMs: 30_000,
    mutation: false,
    responseLimit: MAX_ARTIFACT_RESPONSE_BYTES,
  },
  '/internal/v1/cases/checkpoint': {
    tool: 'analysis_case_checkpoint',
    waiterMs: 30_000,
    hardMs: 120_000,
    mutation: true,
    responseLimit: MAX_MCP_RESPONSE_BYTES,
  },
  '/internal/v1/context/pack': {
    tool: 'analysis_context_pack',
    waiterMs: 30_000,
    hardMs: 30_000,
    mutation: false,
    responseLimit: MAX_MCP_RESPONSE_BYTES,
  },
  '/internal/v1/samples/delete': {
    tool: 'sample_delete',
    waiterMs: 300_000,
    hardMs: 900_000,
    mutation: true,
    responseLimit: MAX_MCP_RESPONSE_BYTES,
  },
})
