fn main() {
    // Embed assets/icon.ico as the exe's resource icon (taskbar, explorer, alt-tab).
    #[cfg(windows)]
    {
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .compile()
            .expect("failed to embed exe icon");
    }
}
