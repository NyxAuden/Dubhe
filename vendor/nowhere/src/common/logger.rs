// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! UTC service information and raw error output.

use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;

static OUTPUT: Mutex<()> = Mutex::new(());

/// 以 UTC 输出 `%Y-%m-%dT%H:%M:%S%.3fZ`（chrono 的等价格式）。
///
/// 替换 chrono 的理由：RUSTSEC-2026-0543 把 chrono 全部版本标为 unmaintained，
/// 而本仓库只用到这一个时间戳格式。手写实现避免引入未维护依赖。
fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total = elapsed.as_secs();
    let millis = elapsed.subsec_millis();
    let days = total / 86_400;
    let seconds_of_day = total % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Howard Hinnant 的 `civil_from_days`：把 Unix 纪元起的天数转成公历年月日。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (year + i64::from(month <= 2), month, day)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Logger;

impl Logger {
    pub fn info(&self, args: fmt::Arguments<'_>) {
        self.write(args, false);
    }

    pub fn error(&self, args: fmt::Arguments<'_>) {
        self.write(args, true);
    }

    pub fn flush(&self) {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
    }

    fn write(&self, args: fmt::Arguments<'_>, error: bool) {
        let line = format!(
            "{} {}\n",
            utc_timestamp(),
            args.to_string().replace('\r', "\\r").replace('\n', "\\n")
        );
        let _guard = OUTPUT.lock().unwrap_or_else(|lock| lock.into_inner());
        if error {
            let _ = io::stderr().write_all(line.as_bytes());
        } else {
            let _ = io::stdout().write_all(line.as_bytes());
        }
    }
}
