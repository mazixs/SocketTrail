// Ресурсы Windows-exe: иконка, сведения о версии, манифест (asInvoker, UTF-8).
// build.rs выполняется на машине сборки, поэтому смотрим целевую ОС, а не cfg.
fn main() {
    println!("cargo:rerun-if-changed=assets/sockettrail.ico");
    println!("cargo:rerun-if-changed=assets/sockettrail.manifest");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/sockettrail.ico")
        .set_manifest_file("assets/sockettrail.manifest")
        .set("ProductName", "SocketTrail")
        .set(
            "FileDescription",
            "SocketTrail - network connections by process",
        )
        .set("CompanyName", "SocketTrail")
        .set("LegalCopyright", "MIT License");
    if let Err(e) = res.compile() {
        panic!("ресурсы Windows не собраны: {e}");
    }
}
