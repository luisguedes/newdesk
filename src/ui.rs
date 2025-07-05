use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/share/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/share/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }
        
    fn verify_login(&self, raw: String, id: String) -> bool {
       crate::verify_login(&raw, &id)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
        fn verify_login(String, String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
