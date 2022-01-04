use std::collections::HashMap;
use std::process::Command;
use async_std::fs::{create_dir_all, File, OpenOptions};
use async_std::io::{BufReader, copy};
use async_std::path::Path;
use async_std::task::spawn;
use checksums::{Algorithm, hash_file};
use regex::Regex;
use sixtyfps::{Image, invoke_from_event_loop, SharedString};
use surf::http::Cookie;
use surf::http::cookies::CookieJar;
use eyre::{eyre, Result};
use serde_json::Value;
use surf::{Body, Client};
use surf::http::mime::FORM;
use tempfile::tempdir;

sixtyfps::sixtyfps!{
    import { Button, LineEdit } from "sixtyfps_widgets.60";
    import "./Password.ttf";
    LaunchFf14 := Window {
        title: "launch-ff14";
        icon: @image-url("pochacco.png");
        width: 180px;
        callback launch(string, string, string);

        property <image> captcha_img: @image-url("");
        property <string> state: "Wait...";
        property <string> state2: "";
        property <string> username <=> username_edit.text;
        property <string> password <=> password_edit.text;
        property <string> captcha <=> captcha_edit.text;

        VerticalLayout {
            username_edit := LineEdit {
                width: parent.width;
                placeholder-text: "Username";
                has-focus: true;
            }
            password_edit := TextInput {
                width: parent.width;
                height: 30px;
                vertical-alignment: center;
                font-family: "Password";
            }
            captcha_edit := LineEdit {
                width: parent.width;
                placeholder-text: "CAPTCHA";
                accepted => { if (root.state == "Launch") {root.launch(root.username, root.password, root.captcha);} }
            }
            Image {
                source: root.captcha_img;
            }
            Button {
                width: parent.width;
                text: root.state + root.state2;
                enabled: root.state == "Launch";
                clicked => { root.launch(root.username, root.password, root.captcha); }
            }
        }
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    let client = Client::new();

    let mut jar = CookieJar::new();
    let mut launcher_response = client.get("https://newlauncher.ff14.co.kr/").await.map_err(|e| eyre!(e))?;
    let set_cookies = launcher_response.header("Set-Cookie").cloned();
    if set_cookies.is_some() {
        for header in set_cookies.unwrap().iter() {
            jar.add(Cookie::parse(header.as_str().to_owned())?)
        }
    }
    let session_id = jar.get("ASP.NET_SessionId").expect("expected ASP.NET_SessionId").to_string();
    let launcher = launcher_response.body_string().await.map_err(|e| eyre!(e))?;
    let vcid = Regex::new("\"BDC_VCID_LauncherLoginCaptcha\" value=\"([0-9a-z]+)\"")
        .unwrap()
        .captures(&launcher).unwrap().get(1).map_or("", |m| m.as_str()).to_owned();
    let hs = Regex::new("\"BDC_Hs_LauncherLoginCaptcha\" value=\"([0-9a-z]+)\"")
        .unwrap()
        .captures(&launcher).unwrap().get(1).map_or("", |m| m.as_str()).to_owned();
    let sp = Regex::new("\"BDC_SP_LauncherLoginCaptcha\" value=\"([0-9a-z]+)\"")
        .unwrap()
        .captures(&launcher).unwrap().get(1).map_or("", |m| m.as_str()).to_owned();
    let tmp_dir = tempdir()?;
    let captcha_path = tmp_dir.path().join("captcha.jpg");
    let mut captcha_file = File::create(&captcha_path).await?;
    copy(&mut BufReader::new(
        client.get(format!("https://newlauncher.ff14.co.kr/BotDetectCaptcha.ashx?get=image&c=LauncherLoginCaptcha&t={}", vcid))
            .header("Cookie", jar.get("ASP.NET_SessionId").ok_or(eyre!("expected ASP.NET_SessionId"))?.to_string())
            .await.map_err(|e| eyre!(e))?
    ), &mut captcha_file).await?;

    let window = LaunchFf14::new();
    window.set_captcha_img(Image::load_from_path(&captcha_path).map_err(|_e| eyre!("LoadImageError"))?);
    let window_weak = window.as_weak();
    window.on_launch(move |username_, password_, captcha_| {
        let window_copy_king = window_weak.clone();
        let window_copy = window_copy_king.clone();
        invoke_from_event_loop(move || window_copy.unwrap().set_state2(SharedString::from("")));
        let session_id = session_id.clone();
        let vcid = vcid.clone();
        let hs = hs.clone();
        let sp = sp.clone();
        let username = username_.to_string();
        let password = password_.to_string();
        let captcha = captcha_.to_string();
        spawn(async move {
            let response = surf::post("https://newlauncher.ff14.co.kr/LauncherFF/LauncherProcess")
                .header("Cookie", session_id.clone())
                .body(Body::from_form(&HashMap::from([
                    ("gameServiceID", "34".to_owned()),
                    ("csiteNo", "0".to_owned()),
                    ("isPcBang", "4".to_owned()),
                    ("hid_freeTrial", "X".to_owned()),
                    ("hid_freeTrialRemainDate", "0".to_owned()),
                    ("cancelFlag", "1".to_owned()),
                    ("chNppAuth", "F".to_owned()),
                    ("decideDX", "1".to_owned()),
                    ("decideAS", "1".to_owned()),
                    ("memberID", username.clone()),
                    ("passWord", password.clone()),
                    ("BDC_VCID_LauncherLoginCaptcha", vcid.clone()),
                    ("BDC_BackWorkaround_LauncherLoginCaptcha", "1".to_owned()),
                    ("BDC_Hs_LauncherLoginCaptcha", hs.clone()),
                    ("BDC_SP_LauncherLoginCaptcha", sp.clone()),
                    ("CaptchaCode", captcha.clone())
                ])).expect("body")).content_type(FORM).recv_json::<Value>().await.expect("response");
            let member_key = response["memberKey"].as_str();
            if member_key.is_none() {
                let window_copy = window_copy_king.clone();
                invoke_from_event_loop(move || window_copy.unwrap().set_state2(SharedString::from(": Login fail")));
            }
            let member_key = member_key.expect("member_key expect").to_string();

            let response = surf::post("https://newlauncher.ff14.co.kr/LauncherFF/MakeToken")
                .header("Cookie", session_id)
                .body(Body::from_form(&HashMap::from([
                    ("gameServiceID", "34".to_owned()),
                    ("csiteNo", "0".to_owned()),
                    ("isPcBang", "4".to_owned()),
                    ("InternetCafeType", "0".to_owned()),
                    ("hid_freeTrial", "X".to_owned()),
                    ("hid_freeTrialRemainDate", "0".to_owned()),
                    ("cancelFlag", "1".to_owned()),
                    ("chNppAuth", "F".to_owned()),
                    ("decideDX", "1".to_owned()),
                    ("decideAS", "1".to_owned()),
                    ("memberID", username.clone()),
                    ("memberKey", member_key.clone()),
                    ("BDC_VCID_LauncherLoginCaptcha", vcid.clone()),
                    ("BDC_BackWorkaround_LauncherLoginCaptcha", "1".to_owned()),
                    ("BDC_Hs_LauncherLoginCaptcha", hs.clone()),
                    ("BDC_SP_LauncherLoginCaptcha", sp.clone()),
                    ("CaptchaCode", captcha.clone())
                ])).expect("body")).content_type(FORM).recv_json::<Value>().await.expect("response");
            let token = response["toKen"].as_str().expect("toKen should be a string").to_string();
            assert!(Regex::new("^[A-Za-z0-9+/=]{44}$").unwrap().is_match(token.as_str()));
            Command::new(".\\game\\ffxiv_dx11.exe")
                .args([
                    "DEV.LobbyHost01=lobbyf-live.ff14.co.kr",
                    "DEV.LobbyPort01=54994",
                    "DEV.GMServerHost=gm-live.ff14.co.kr",
                    &format!("DEV.TestSID={}", token),
                    "SYS.resetConfig=0",
                    "DEV.SaveDataBankHost=config-dl-live.ff14.co.kr"
                ]).spawn().expect("failed to execute process");
        });
    });

    let window_weak = window.as_weak();
    spawn(async move {
        let file_list_resp = client.get("https://fcdp.ff14.co.kr/FileListGame.json").recv_json::<Value>().await.map_err(|e| eyre!(e))?;
        let file_list_obj = file_list_resp.as_object().ok_or(eyre!("FileListGame"))?;
        let base_url = file_list_obj["URL"].as_str().ok_or(eyre!("URL"))?.to_owned();
        let file_list = file_list_obj["FileList"].as_array().ok_or(eyre!("FileList"))?.to_owned();
        let len = file_list.len();
        let mut should_check_checksum = false;
        for (idx, file_info) in file_list.iter().enumerate() {
            let window_copy = window_weak.clone();
            invoke_from_event_loop(move || window_copy.unwrap().set_state(SharedString::from(format!("Chk {}/{}", idx + 1, len))));
            let name = file_info.as_object().ok_or(eyre!("obj"))?["Name"].as_str().ok_or(eyre!("Name"))?;
            let size = file_info.as_object().ok_or(eyre!("obj"))?["Size"].as_u64().ok_or(eyre!("Size"))?;
            assert!(!name.contains(".."));

            let path_str = format!("{}{}", "./game/", &name);
            let path = Path::new(&path_str);
            create_dir_all(path.parent().ok_or(eyre!("no parent"))?).await?;
            if !path.exists().await || path.metadata().await?.len() != size {
                let window_copy = window_weak.clone();
                invoke_from_event_loop(move || window_copy.unwrap().set_state(SharedString::from(format!("Dwn {}/{}", idx + 1, len))));
                should_check_checksum = true;
                let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path).await?;
                copy(&mut BufReader::new(
                    client.get(format!("{}{}", base_url, name)).await.map_err(|e| eyre!(e))?
                ), &mut file).await?;
            }
        }
        if should_check_checksum && false { // Currently don't use checksum
            for (idx, file_info) in file_list.iter().enumerate() {
                let window_copy = window_weak.clone();
                invoke_from_event_loop(move || window_copy.unwrap().set_state(SharedString::from(format!("(CS) Chk {}/{}", idx + 1, len))));
                let name = file_info.as_object().ok_or(eyre!("obj"))?["Name"].as_str().ok_or(eyre!("Name"))?;
                let size = file_info.as_object().ok_or(eyre!("obj"))?["Size"].as_u64().ok_or(eyre!("Size"))?;
                let checksum = file_info.as_object().ok_or(eyre!("obj"))?["CheckSum"].as_str().ok_or(eyre!("checksum"))?;
                assert!(!name.contains(".."));

                let path_str = &format!("{}{}", "./game/", name);
                let path = Path::new(path_str);
                create_dir_all(path.parent().ok_or(eyre!("no parent"))?).await?;
                if !path.exists().await || path.metadata().await?.len() != size || hash_file(path.into(), Algorithm::MD5) != checksum {
                    let window_copy = window_weak.clone();
                    invoke_from_event_loop(move || window_copy.unwrap().set_state(SharedString::from(format!("(CS) Dwn {}/{}", idx + 1, len))));
                    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path).await?;
                    copy(&mut BufReader::new(
                        client.get(format!("{}{}", base_url, name)).await.map_err(|e| eyre!(e))?
                    ), &mut file).await?;
                }
            }
        }

        let window_copy = window_weak.clone();
        invoke_from_event_loop(move || window_copy.unwrap().set_state(SharedString::from("Launch")));
        Result::<()>::Ok(())
    });

    window.run();
    Result::Ok(())
}
