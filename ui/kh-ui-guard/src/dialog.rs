//! ガード確認用フリクションダイアログモジュール

use crate::error::Result;
use kh_domain::model::{FrictionSettings, Language};
use kh_ui_common::i18n;

/// プロンプトダイアログのコンテキスト
#[derive(Debug, Clone)]
pub struct PromptContext {
    pub target: String,
    pub args: Vec<String>,
    pub resolved_path: Option<String>,
    pub username: String,
    pub session_name: String,
    pub nudge_text: Option<String>,
    pub timeout_seconds: Option<u32>,
    /// UI言語設定
    pub language: Language,
}

/// プロンプトダイアログの結果
#[derive(Debug, Clone)]
pub struct PromptOutcome {
    pub allowed: bool,
    pub reason: String,
    pub emergency: bool,
}

/// フリクションダイアログを表示してユーザー決定を取得
pub fn show_prompt(options: &FrictionSettings, ctx: &PromptContext) -> Result<PromptOutcome> {
    // 言語設定を適用
    i18n::set_language(ctx.language);

    #[cfg(target_os = "windows")]
    {
        win32_dialog::run_prompt(options, ctx)
    }
    #[cfg(not(target_os = "windows"))]
    {
        cli_fallback::run_prompt(options, ctx)
    }
}

#[cfg(target_os = "windows")]
mod win32_dialog {
    use super::{FrictionSettings, PromptContext, PromptOutcome};
    use crate::error::{Result, err};
    use kh_ui_common::i18n::t;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM,
    };
    use windows::Win32::Graphics::Gdi::*;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::HiDpi::*;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::PCWSTR;

    const fn rgb(r: u8, g: u8, b: u8) -> u32 {
        (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
    }

    const BG: u32 = rgb(255, 255, 255);
    const CARD_BG: u32 = rgb(250, 250, 250);
    const BORDER: u32 = rgb(228, 228, 231);
    const TEXT_PRIMARY: u32 = rgb(9, 9, 11);
    const TEXT_SECONDARY: u32 = rgb(39, 39, 42);
    const TEXT_MUTED: u32 = rgb(113, 113, 122);
    const BTN_PRIMARY_BG: u32 = rgb(24, 24, 27);
    const BTN_PRIMARY_HOVER: u32 = rgb(39, 39, 42);
    const BTN_PRIMARY_TEXT: u32 = rgb(250, 250, 250);
    const BTN_SECONDARY_BG: u32 = rgb(255, 255, 255);
    const BTN_SECONDARY_HOVER: u32 = rgb(244, 244, 245);
    const BTN_SECONDARY_BORDER: u32 = rgb(228, 228, 231);
    const BTN_SECONDARY_TEXT: u32 = rgb(24, 24, 27);
    const BTN_DISABLED_BG: u32 = rgb(244, 244, 245);
    const BTN_DISABLED_TEXT: u32 = rgb(161, 161, 170);
    const PROGRESS_TRACK: u32 = rgb(228, 228, 231);
    const PROGRESS_FILL: u32 = rgb(24, 24, 27);

    const TIMER_ID: usize = 42;
    const WINDOW_W: i32 = 420;
    const WINDOW_H: i32 = 320;
    const PAD: i32 = 24;

    #[derive(Clone, Copy, Default)]
    struct BtnState {
        hover: bool,
        pressed: bool,
    }

    struct WinState {
        ctx: PromptContext,
        hold_req: bool,
        ptr_req: bool,
        emerg_en: bool,
        hold_ms: u32,
        emerg_ms: u32,
        ptr_thresh: u32,
        hold_active: bool,
        hold_start: Option<Instant>,
        hold_done: bool,
        hold_prog: f32,
        ptr_origin: POINT,
        ptr_dist: f64,
        ptr_done: bool,
        ptr_prog: f32,
        hold_bar_rc: Option<RECT>,
        ptr_bar_rc: Option<RECT>,
        emerg_start: Option<Instant>,
        emerg_done: bool,
        allow_en: bool,
        btn_allow: BtnState,
        btn_cancel: BtnState,
        btn_allow_rc: RECT,
        btn_cancel_rc: RECT,
        font_title: HFONT,
        font_body: HFONT,
        font_label: HFONT,
        font_btn: HFONT,
        scale: f32,
        outcome: Option<PromptOutcome>,
        timeout_secs: Option<u32>,
        dialog_start: Instant,
    }

    impl WinState {
        fn new(opt: &FrictionSettings, ctx: &PromptContext, scale: f32) -> Self {
            let m = |x: i32| ((x as f32) * scale) as i32;
            Self {
                ctx: ctx.clone(),
                hold_req: opt.require_hold(),
                ptr_req: opt.require_pointer_movement(),
                emerg_en: opt.emergency_bypass(),
                hold_ms: opt.hold_ms(),
                emerg_ms: opt.emergency_hold_ms(),
                ptr_thresh: opt.pointer_move_threshold_px(),
                hold_active: false,
                hold_start: None,
                hold_done: false,
                hold_prog: 0.0,
                ptr_origin: POINT::default(),
                ptr_dist: 0.0,
                ptr_done: false,
                ptr_prog: 0.0,
                hold_bar_rc: None,
                ptr_bar_rc: None,
                emerg_start: None,
                emerg_done: false,
                allow_en: !opt.require_hold() && !opt.require_pointer_movement(),
                btn_allow: BtnState::default(),
                btn_cancel: BtnState::default(),
                btn_allow_rc: RECT::default(),
                btn_cancel_rc: RECT::default(),
                font_title: mk_font(m(-18), FW_MEDIUM.0 as i32),
                font_body: mk_font(m(-14), FW_NORMAL.0 as i32),
                font_label: mk_font(m(-12), FW_MEDIUM.0 as i32),
                font_btn: mk_font(m(-14), FW_MEDIUM.0 as i32),
                scale,
                outcome: None,
                timeout_secs: ctx.timeout_seconds,
                dialog_start: Instant::now(),
            }
        }
        /// allow_enを更新し変更有無を返す
        fn upd_allow(&mut self) -> bool {
            let prev = self.allow_en;
            let h = !self.hold_req || self.hold_done;
            let p = !self.ptr_req || self.ptr_done;
            self.allow_en = h && p;
            self.allow_en != prev
        }
    }

    impl Drop for WinState {
        fn drop(&mut self) {
            unsafe {
                if !self.font_title.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(self.font_title.0));
                }
                if !self.font_body.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(self.font_body.0));
                }
                if !self.font_label.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(self.font_label.0));
                }
                if !self.font_btn.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(self.font_btn.0));
                }
            }
        }
    }

    #[derive(Default, Debug)]
    struct RedrawFlags {
        any: bool,
        hold: bool,
        ptr: bool,
        btn: bool,
    }

    pub fn run_prompt(opt: &FrictionSettings, ctx: &PromptContext) -> Result<PromptOutcome> {
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
        let hmod = unsafe { GetModuleHandleW(None)? };
        let hinst = HINSTANCE(hmod.0);
        let cls = wstr("KHGuardOSS");
        reg_class(hinst, &cls)?;

        let scale = unsafe {
            let hdc = GetDC(None);
            let dpi = if !hdc.is_invalid() {
                GetDeviceCaps(Some(hdc), LOGPIXELSX)
            } else {
                96
            };
            if !hdc.is_invalid() {
                ReleaseDC(None, hdc);
            }
            dpi as f32 / 96.0
        };
        let m = |x: i32| ((x as f32) * scale) as i32;
        let st = Box::new(WinState::new(opt, ctx, scale));
        let sp = Box::into_raw(st);
        unsafe {
            let s = &mut *sp;
            let _ = GetCursorPos(&mut s.ptr_origin);
        }

        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOPMOST,
                PCWSTR(cls.as_ptr()),
                PCWSTR(wstr(t().guard_title()).as_ptr()),
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                m(WINDOW_W),
                m(WINDOW_H),
                None,
                None,
                Some(hinst),
                Some(sp as *const c_void),
            )
        };
        let hwnd = match hwnd {
            Ok(h) => h,
            Err(_) => {
                unsafe {
                    drop(Box::from_raw(sp));
                }
                return Err(err("window create failed"));
            }
        };
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOW);
        }

        let mut msg = MSG::default();
        while unsafe { GetMessageW(&mut msg, None, 0, 0) }.as_bool() {
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let sr = unsafe { &mut *sp };
            if let Some(o) = sr.outcome.take() {
                unsafe {
                    let _ = DestroyWindow(hwnd);
                    drop(Box::from_raw(sp));
                }
                return Ok(o);
            }
        }
        unsafe {
            drop(Box::from_raw(sp));
        }
        Ok(PromptOutcome {
            allowed: false,
            reason: "window-closed".into(),
            emergency: false,
        })
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_CREATE => unsafe {
                let cs = &*(lp.0 as *const CREATESTRUCTW);
                let sp = cs.lpCreateParams as *mut WinState;
                let _ = SetWindowLongPtrW(hwnd, GWL_USERDATA, sp as isize);
                // 20fps程度で十分。状態変化時のみ再描画。
                let _ = SetTimer(Some(hwnd), TIMER_ID, 50, None);
                LRESULT(0)
            },
            WM_TIMER => unsafe {
                let s = &mut *get_st(hwnd);
                let rf = tick(s);
                if rf.any {
                    if rf.hold {
                        if let Some(rc) = &s.hold_bar_rc {
                            let _ = InvalidateRect(Some(hwnd), Some(rc), false);
                        } else {
                            let _ = InvalidateRect(Some(hwnd), None, false);
                        }
                    }
                    if rf.ptr {
                        if let Some(rc) = &s.ptr_bar_rc {
                            let _ = InvalidateRect(Some(hwnd), Some(rc), false);
                        } else {
                            let _ = InvalidateRect(Some(hwnd), None, false);
                        }
                    }
                    if rf.btn {
                        let _ = InvalidateRect(Some(hwnd), Some(&s.btn_allow_rc), false);
                        let _ = InvalidateRect(Some(hwnd), Some(&s.btn_cancel_rc), false);
                    }
                    if !(rf.hold || rf.ptr || rf.btn) {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            },
            WM_ERASEBKGND => {
                // 全クライアント領域を自前で再描画（ダブルバッファリング使用）
                // 背景消去不要と通知してちらつき軽減
                LRESULT(1)
            }
            WM_MOUSEMOVE => unsafe {
                let s = &mut *get_st(hwnd);
                let mut pt = POINT::default();
                let _ = GetCursorPos(&mut pt);
                // 原点からの最大距離を追跡（進捗は減らない、ポインタが戻っても完了状態を維持）
                let mut dirty = false;
                if !s.ptr_done {
                    let dx = (pt.x - s.ptr_origin.x) as f64;
                    let dy = (pt.y - s.ptr_origin.y) as f64;
                    s.ptr_dist = (dx * dx + dy * dy).sqrt();
                    let prog = (s.ptr_dist / s.ptr_thresh as f64).min(1.0) as f32;
                    if prog > s.ptr_prog + f32::EPSILON {
                        s.ptr_prog = prog;
                        dirty = true;
                    }
                    if s.ptr_dist >= s.ptr_thresh as f64 {
                        s.ptr_done = true;
                        s.ptr_prog = 1.0;
                        let _ = s.upd_allow();
                        dirty = true;
                    }
                }
                let x = (lp.0 & 0xFFFF) as i16 as i32;
                let y = ((lp.0 >> 16) & 0xFFFF) as i16 as i32;
                let prev_allow = s.btn_allow.hover;
                let prev_cancel = s.btn_cancel.hover;
                s.btn_allow.hover = pt_in(x, y, &s.btn_allow_rc);
                s.btn_cancel.hover = pt_in(x, y, &s.btn_cancel_rc);
                if dirty {
                    if let Some(rc) = &s.ptr_bar_rc {
                        let _ = InvalidateRect(Some(hwnd), Some(rc), false);
                    } else {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                if prev_allow != s.btn_allow.hover || prev_cancel != s.btn_cancel.hover {
                    let _ = InvalidateRect(Some(hwnd), Some(&s.btn_allow_rc), false);
                    let _ = InvalidateRect(Some(hwnd), Some(&s.btn_cancel_rc), false);
                }
                LRESULT(0)
            },
            WM_LBUTTONDOWN => unsafe {
                let s = &mut *get_st(hwnd);
                let x = (lp.0 & 0xFFFF) as i16 as i32;
                let y = ((lp.0 >> 16) & 0xFFFF) as i16 as i32;
                if pt_in(x, y, &s.btn_allow_rc) {
                    s.btn_allow.pressed = true;
                } else if pt_in(x, y, &s.btn_cancel_rc) {
                    s.btn_cancel.pressed = true;
                }
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            },
            WM_LBUTTONUP => unsafe {
                let s = &mut *get_st(hwnd);
                let x = (lp.0 & 0xFFFF) as i16 as i32;
                let y = ((lp.0 >> 16) & 0xFFFF) as i16 as i32;
                if s.btn_allow.pressed && pt_in(x, y, &s.btn_allow_rc) && s.allow_en {
                    s.outcome = Some(PromptOutcome {
                        allowed: true,
                        reason: "user-allowed".into(),
                        emergency: s.emerg_done,
                    });
                } else if s.btn_cancel.pressed && pt_in(x, y, &s.btn_cancel_rc) {
                    s.outcome = Some(PromptOutcome {
                        allowed: false,
                        reason: "user-cancelled".into(),
                        emergency: false,
                    });
                }
                s.btn_allow.pressed = false;
                s.btn_cancel.pressed = false;
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            },
            WM_PAINT => unsafe {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let s = &mut *get_st(hwnd);

                // ダブルバッファリング: メモリDCに描画後Blit
                let width = rc.right - rc.left;
                let height = rc.bottom - rc.top;
                if width > 0 && height > 0 {
                    let memdc = CreateCompatibleDC(Some(hdc));
                    if !memdc.is_invalid() {
                        let hbmp = CreateCompatibleBitmap(hdc, width, height);
                        if !hbmp.is_invalid() {
                            let old = SelectObject(memdc, HGDIOBJ(hbmp.0));
                            paint(memdc, &rc, s);
                            let _ = BitBlt(hdc, 0, 0, width, height, Some(memdc), 0, 0, SRCCOPY);
                            let _ = SelectObject(memdc, old);
                            let _ = DeleteObject(HGDIOBJ(hbmp.0));
                        } else {
                            // ビットマップ確保失敗時は直接描画にフォールバック
                            paint(hdc, &rc, s);
                        }
                        let _ = DeleteDC(memdc);
                    } else {
                        paint(hdc, &rc, s);
                    }
                } else {
                    paint(hdc, &rc, s);
                }
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            },
            WM_DESTROY => unsafe {
                PostQuitMessage(0);
                LRESULT(0)
            },
            _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
        }
    }

    fn paint(hdc: HDC, rc: &RECT, s: &mut WinState) {
        let scale = s.scale;
        let m = |x: i32| ((x as f32) * scale) as i32;
        unsafe {
            let bg = CreateSolidBrush(COLORREF(BG));
            FillRect(hdc, rc, bg);
            let _ = DeleteObject(HGDIOBJ(bg.0));
            let _ = SetBkMode(hdc, TRANSPARENT);
        }
        let l = m(PAD);
        let r = rc.right - m(PAD);
        let mut y = m(PAD);

        // タイトル
        unsafe {
            let _ = SelectObject(hdc, HGDIOBJ(s.font_title.0));
            let _ = SetTextColor(hdc, COLORREF(TEXT_PRIMARY));
        }
        let mut title_text = wstr(t().guard_process_confirmation());
        let mut tr = RECT {
            left: l,
            top: y,
            right: r,
            bottom: y + m(28),
        };
        unsafe {
            DrawTextW(hdc, &mut title_text, &mut tr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        }
        y += m(36);

        // カード
        let mut ch = m(60);
        if s.ctx.nudge_text.is_some() {
            ch += m(50);
        }
        let cr = RECT {
            left: l,
            top: y,
            right: r,
            bottom: y + ch,
        };
        draw_card(hdc, &cr, m(8));
        unsafe {
            let _ = SelectObject(hdc, HGDIOBJ(s.font_body.0));
        }
        let cp = m(12);
        let mut ty = y + cp;
        unsafe {
            let _ = SetTextColor(hdc, COLORREF(TEXT_PRIMARY));
        }
        let disp = s.ctx.resolved_path.as_deref().unwrap_or(&s.ctx.target);
        let disp = if disp.len() > 45 {
            format!("...{}", &disp[disp.len() - 42..])
        } else {
            disp.to_string()
        };
        let mut ts = wstr(&disp);
        let mut tsr = RECT {
            left: l + cp,
            top: ty,
            right: r - cp,
            bottom: ty + m(20),
        };
        unsafe {
            DrawTextW(hdc, &mut ts, &mut tsr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        }
        ty += m(22);
        unsafe {
            let _ = SelectObject(hdc, HGDIOBJ(s.font_label.0));
            let _ = SetTextColor(hdc, COLORREF(TEXT_MUTED));
        }
        let mut us = wstr(&format!("{} | {}", s.ctx.username, s.ctx.session_name));
        let mut usr = RECT {
            left: l + cp,
            top: ty,
            right: r - cp,
            bottom: ty + m(18),
        };
        unsafe {
            DrawTextW(hdc, &mut us, &mut usr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        }
        ty += m(18);
        if let Some(text) = s.ctx.nudge_text.as_deref() {
            unsafe {
                let _ = SelectObject(hdc, HGDIOBJ(s.font_body.0));
                let _ = SetTextColor(hdc, COLORREF(TEXT_SECONDARY));
            }
            let mut ns = wstr(text);
            let mut nsr = RECT {
                left: l + cp,
                top: ty,
                right: r - cp,
                bottom: ty + m(48),
            };
            unsafe {
                DrawTextW(hdc, &mut ns, &mut nsr, DT_LEFT | DT_WORDBREAK);
            }
        }
        y += ch + m(16);

        // 進捗セクション
        if s.hold_req {
            let (ny, br) = draw_prog(
                hdc,
                s,
                l,
                r,
                y,
                t().guard_hold_instruction(),
                s.hold_prog,
                s.hold_done,
            );
            s.hold_bar_rc = Some(br);
            y = ny;
            y += m(12);
        }
        if s.ptr_req {
            let (ny, br) = draw_prog(hdc, s, l, r, y, t().guard_move_instruction(), s.ptr_prog, s.ptr_done);
            s.ptr_bar_rc = Some(br);
            y = ny;
            y += m(12);
        }
        if s.emerg_en && !s.emerg_done {
            unsafe {
                let _ = SelectObject(hdc, HGDIOBJ(s.font_label.0));
                let _ = SetTextColor(hdc, COLORREF(TEXT_MUTED));
            }
            let mut h = wstr(t().guard_emergency_instruction());
            let mut hr = RECT {
                left: l,
                top: y,
                right: r,
                bottom: y + m(16),
            };
            unsafe {
                DrawTextW(hdc, &mut h, &mut hr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
            }
        }

        // ボタン
        let bh = m(36);
        let bw = m(100);
        let bg = m(12);
        let by = rc.bottom - m(PAD) - bh;
        s.btn_cancel_rc = RECT {
            left: r - bw * 2 - bg,
            top: by,
            right: r - bw - bg,
            bottom: by + bh,
        };
        draw_btn_sec(
            hdc,
            &s.btn_cancel_rc,
            t().guard_cancel(),
            &s.btn_cancel,
            s.font_btn,
            m(6),
        );
        s.btn_allow_rc = RECT {
            left: r - bw,
            top: by,
            right: r,
            bottom: by + bh,
        };
        draw_btn_pri(
            hdc,
            &s.btn_allow_rc,
            t().guard_allow(),
            &s.btn_allow,
            s.allow_en,
            s.font_btn,
            m(6),
        );
    }

    fn draw_prog(
        hdc: HDC,
        s: &mut WinState,
        l: i32,
        r: i32,
        y: i32,
        lbl: &str,
        prog: f32,
        done: bool,
    ) -> (i32, RECT) {
        let scale = s.scale;
        let m = |x: i32| ((x as f32) * scale) as i32;
        unsafe {
            let _ = SelectObject(hdc, HGDIOBJ(s.font_label.0));
            let _ = SetTextColor(
                hdc,
                if done {
                    COLORREF(TEXT_MUTED)
                } else {
                    COLORREF(TEXT_SECONDARY)
                },
            );
        }
        let lt = if done {
            format!("{} {}", lbl, t().guard_ok())
        } else {
            lbl.to_string()
        };
        let mut ls = wstr(&lt);
        let mut lr = RECT {
            left: l,
            top: y,
            right: r,
            bottom: y + m(18),
        };
        unsafe {
            DrawTextW(hdc, &mut ls, &mut lr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        }
        let by = y + m(20);
        let bh = m(6);
        let br = RECT {
            left: l,
            top: by,
            right: r,
            bottom: by + bh,
        };
        draw_bar(hdc, &br, prog, m(4));
        (by + bh, br)
    }

    fn draw_card(hdc: HDC, rc: &RECT, rad: i32) {
        unsafe {
            let br = CreateSolidBrush(COLORREF(CARD_BG));
            let pn = CreatePen(PS_SOLID, 1, COLORREF(BORDER));
            let ob = SelectObject(hdc, HGDIOBJ(br.0));
            let op = SelectObject(hdc, HGDIOBJ(pn.0));
            let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
            let _ = SelectObject(hdc, ob);
            let _ = SelectObject(hdc, op);
            let _ = DeleteObject(HGDIOBJ(br.0));
            let _ = DeleteObject(HGDIOBJ(pn.0));
        }
    }

    fn draw_bar(hdc: HDC, rc: &RECT, prog: f32, rad: i32) {
        unsafe {
            let tb = CreateSolidBrush(COLORREF(PROGRESS_TRACK));
            let tp = CreatePen(PS_SOLID, 0, COLORREF(PROGRESS_TRACK));
            let ob = SelectObject(hdc, HGDIOBJ(tb.0));
            let op = SelectObject(hdc, HGDIOBJ(tp.0));
            let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
            if prog > 0.0 {
                let fw = ((rc.right - rc.left) as f32 * prog) as i32;
                if fw > rad * 2 {
                    let fb = CreateSolidBrush(COLORREF(PROGRESS_FILL));
                    let fp = CreatePen(PS_SOLID, 0, COLORREF(PROGRESS_FILL));
                    let _ = SelectObject(hdc, HGDIOBJ(fb.0));
                    let _ = SelectObject(hdc, HGDIOBJ(fp.0));
                    let _ = RoundRect(hdc, rc.left, rc.top, rc.left + fw, rc.bottom, rad, rad);
                    let _ = DeleteObject(HGDIOBJ(fb.0));
                    let _ = DeleteObject(HGDIOBJ(fp.0));
                }
            }
            let _ = SelectObject(hdc, ob);
            let _ = SelectObject(hdc, op);
            let _ = DeleteObject(HGDIOBJ(tb.0));
            let _ = DeleteObject(HGDIOBJ(tp.0));
        }
    }

    fn draw_btn_pri(hdc: HDC, rc: &RECT, txt: &str, bs: &BtnState, en: bool, fnt: HFONT, rad: i32) {
        let (bgc, tc) = if !en {
            (BTN_DISABLED_BG, BTN_DISABLED_TEXT)
        } else if bs.pressed {
            (BTN_PRIMARY_BG, BTN_PRIMARY_TEXT)
        } else if bs.hover {
            (BTN_PRIMARY_HOVER, BTN_PRIMARY_TEXT)
        } else {
            (BTN_PRIMARY_BG, BTN_PRIMARY_TEXT)
        };
        unsafe {
            let br = CreateSolidBrush(COLORREF(bgc));
            let pn = CreatePen(PS_SOLID, 0, COLORREF(bgc));
            let ob = SelectObject(hdc, HGDIOBJ(br.0));
            let op = SelectObject(hdc, HGDIOBJ(pn.0));
            let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
            let _ = SelectObject(hdc, HGDIOBJ(fnt.0));
            let _ = SetTextColor(hdc, COLORREF(tc));
            let mut ts = wstr(txt);
            let mut tr = *rc;
            DrawTextW(
                hdc,
                &mut ts,
                &mut tr,
                DT_CENTER | DT_SINGLELINE | DT_VCENTER,
            );
            let _ = SelectObject(hdc, ob);
            let _ = SelectObject(hdc, op);
            let _ = DeleteObject(HGDIOBJ(br.0));
            let _ = DeleteObject(HGDIOBJ(pn.0));
        }
    }

    fn draw_btn_sec(hdc: HDC, rc: &RECT, txt: &str, bs: &BtnState, fnt: HFONT, rad: i32) {
        let bgc = if bs.pressed || bs.hover {
            BTN_SECONDARY_HOVER
        } else {
            BTN_SECONDARY_BG
        };
        unsafe {
            let br = CreateSolidBrush(COLORREF(bgc));
            let pn = CreatePen(PS_SOLID, 1, COLORREF(BTN_SECONDARY_BORDER));
            let ob = SelectObject(hdc, HGDIOBJ(br.0));
            let op = SelectObject(hdc, HGDIOBJ(pn.0));
            let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, rad, rad);
            let _ = SelectObject(hdc, HGDIOBJ(fnt.0));
            let _ = SetTextColor(hdc, COLORREF(BTN_SECONDARY_TEXT));
            let mut ts = wstr(txt);
            let mut tr = *rc;
            DrawTextW(
                hdc,
                &mut ts,
                &mut tr,
                DT_CENTER | DT_SINGLELINE | DT_VCENTER,
            );
            let _ = SelectObject(hdc, ob);
            let _ = SelectObject(hdc, op);
            let _ = DeleteObject(HGDIOBJ(br.0));
            let _ = DeleteObject(HGDIOBJ(pn.0));
        }
    }

    fn tick(s: &mut WinState) -> RedrawFlags {
        let mut rf = RedrawFlags::default();
        if let Some(limit) = s.timeout_secs {
            if s.dialog_start.elapsed() >= Duration::from_secs(limit as u64) && s.outcome.is_none()
            {
                s.outcome = Some(PromptOutcome {
                    allowed: false,
                    reason: "timeout".into(),
                    emergency: false,
                });
                rf.any = true;
                return rf;
            }
        }
        let esc = unsafe { GetAsyncKeyState(VK_ESCAPE.0 as i32) as u16 & 0x8000 != 0 };
        if esc && s.outcome.is_none() {
            s.outcome = Some(PromptOutcome {
                allowed: false,
                reason: "user-cancelled".into(),
                emergency: false,
            });
            rf.any = true;
            return rf;
        }
        if s.hold_req && !s.hold_done {
            let md = unsafe { GetAsyncKeyState(VK_LBUTTON.0 as i32) as u16 & 0x8000 != 0 };
            let sd = unsafe { GetAsyncKeyState(VK_SPACE.0 as i32) as u16 & 0x8000 != 0 };
            let act = md || sd;
            if act && !s.hold_active {
                s.hold_active = true;
                s.hold_start = Some(Instant::now());
                rf.hold = true;
            }
            if !act && s.hold_active {
                s.hold_active = false;
                s.hold_start = None;
                // 30%未満なら進捗リセット
                // 30%以上では誤リリース時のストレス軽減のため進捗維持
                if s.hold_prog < 0.3 {
                    s.hold_prog = 0.0;
                    rf.hold = true;
                }
            }
            if s.hold_active {
                if let Some(st) = s.hold_start {
                    // フレームレート依存を避けるため実経過時間ベースで進捗
                    let el = st.elapsed().as_millis() as f32;
                    let new_prog = (el / s.hold_ms as f32).min(1.0);
                    if (new_prog - s.hold_prog).abs() > f32::EPSILON {
                        s.hold_prog = new_prog;
                        rf.hold = true;
                    }
                    if s.hold_prog >= 1.0 {
                        s.hold_done = true;
                        s.hold_active = false;
                        s.hold_start = None;
                        s.hold_prog = 1.0;
                        let allow_changed = s.upd_allow();
                        rf.hold = true;
                        if allow_changed {
                            rf.btn = true;
                        }
                    }
                }
            }
        }
        if s.emerg_en && !s.emerg_done {
            let c = unsafe { GetAsyncKeyState(VK_CONTROL.0 as i32) as u16 & 0x8000 != 0 };
            let sh = unsafe { GetAsyncKeyState(VK_SHIFT.0 as i32) as u16 & 0x8000 != 0 };
            let a = unsafe { GetAsyncKeyState(VK_MENU.0 as i32) as u16 & 0x8000 != 0 };
            if c && sh && a {
                if s.emerg_start.is_none() {
                    s.emerg_start = Some(Instant::now());
                }
                if s.emerg_start
                    .map(|t| t.elapsed() >= std::time::Duration::from_millis(s.emerg_ms as u64))
                    .unwrap_or(false)
                {
                    s.emerg_done = true;
                    s.allow_en = true;
                    rf.btn = true;
                }
            } else {
                s.emerg_start = None;
            }
        }
        rf.any = rf.hold || rf.ptr || rf.btn;
        rf
    }

    fn mk_font(h: i32, w: i32) -> HFONT {
        unsafe {
            CreateFontW(
                h,
                0,
                0,
                0,
                w,
                0,
                0,
                0,
                DEFAULT_CHARSET,
                OUT_OUTLINE_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                VARIABLE_PITCH.0 as u32,
                PCWSTR(wstr("Segoe UI").as_ptr()),
            )
        }
    }

    fn pt_in(x: i32, y: i32, rc: &RECT) -> bool {
        x >= rc.left && x < rc.right && y >= rc.top && y < rc.bottom
    }

    fn reg_class(hi: HINSTANCE, nm: &[u16]) -> Result<()> {
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: WNDCLASS_STYLES(0),
            lpfnWndProc: Some(wndproc),
            hInstance: hi,
            lpszClassName: PCWSTR(nm.as_ptr()),
            hCursor: unsafe { LoadCursorW(None, IDC_ARROW).unwrap_or_default() },
            hbrBackground: HBRUSH(std::ptr::null_mut()),
            ..Default::default()
        };
        unsafe {
            let _ = RegisterClassExW(&wc);
        }
        Ok(())
    }

    fn wstr(s: impl AsRef<str>) -> Vec<u16> {
        let mut v: Vec<u16> = s.as_ref().encode_utf16().collect();
        v.push(0);
        v
    }
    fn get_st(hwnd: HWND) -> *mut WinState {
        unsafe { GetWindowLongPtrW(hwnd, GWL_USERDATA) as *mut WinState }
    }
}

#[cfg(not(target_os = "windows"))]
mod cli_fallback {
    use super::{FrictionSettings, PromptContext, PromptOutcome};
    use crate::error::{Result, err};
    use kh_ui_common::i18n::t;
    use std::io::{self, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    pub fn run_prompt(opt: &FrictionSettings, ctx: &PromptContext) -> Result<PromptOutcome> {
        println!("\n=== {} ===", t().guard_title());
        println!("{}: {}", t().guard_cli_target(), ctx.target);
        if !ctx.args.is_empty() {
            println!("{}: {}", t().guard_cli_args(), ctx.args.join(" "));
        }
        if let Some(p) = &ctx.resolved_path {
            println!("{}: {}", t().guard_cli_path(), p);
        }
        println!(
            "{}: {} @ {}",
            t().guard_cli_user(),
            ctx.username,
            ctx.session_name
        );
        if let Some(nudge) = &ctx.nudge_text {
            println!("{}: {}", t().guard_cli_message(), nudge);
        }
        if opt.require_hold() {
            println!("\n{}", t().guard_cli_simulating_hold(opt.hold_ms() as u64));
            std::thread::sleep(std::time::Duration::from_millis(opt.hold_ms() as u64));
            println!("{}", t().guard_cli_hold_complete());
        }
        println!("\n{}", t().guard_cli_allow_prompt());
        print!("{}", t().guard_cli_prompt());
        io::stdout().flush()?;
        let input = if let Some(limit) = ctx.timeout_seconds {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let mut inp = String::new();
                let _ = io::stdin().read_line(&mut inp);
                let _ = tx.send(inp);
            });
            match rx.recv_timeout(Duration::from_secs(limit as u64)) {
                Ok(val) => val,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Ok(PromptOutcome {
                        allowed: false,
                        reason: "timeout".into(),
                        emergency: false,
                    });
                }
                Err(e) => return Err(err(format!("stdin read failed: {e}"))),
            }
        } else {
            let mut inp = String::new();
            io::stdin().read_line(&mut inp)?;
            inp
        };
        let ok = matches!(input.trim().to_lowercase().as_str(), "y" | "yes");
        Ok(PromptOutcome {
            allowed: ok,
            reason: if ok { "user-allowed" } else { "user-cancelled" }.into(),
            emergency: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_creation() {
        let ctx = PromptContext {
            target: "test.exe".into(),
            args: vec![],
            resolved_path: None,
            username: "u".into(),
            session_name: "s".into(),
            nudge_text: None,
            timeout_seconds: None,
            language: Language::default(),
        };
        assert_eq!(ctx.target, "test.exe");
    }

    #[test]
    fn outcome_allowed() {
        let o = PromptOutcome {
            allowed: true,
            reason: "ok".into(),
            emergency: false,
        };
        assert!(o.allowed);
    }
}
