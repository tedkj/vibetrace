//! CSV in the user's own list separator and decimal symbol (Windows' regional settings, the ones
//! Excel opens a .csv with): a Norwegian Excel opens "a;b;1,5" as three columns, "a,b,1.5" as
//! one. The family rule (2026-10-22), VibeWiFi's `CsvFormat` copied (no shared code at run time).

/// The separators a CSV is written with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsvFormat {
    pub sep: String,
    pub dec: String,
}

impl Default for CsvFormat {
    fn default() -> Self {
        CsvFormat { sep: ",".into(), dec: ".".into() }
    }
}

impl CsvFormat {
    /// The locale's list separator (LOCALE_SLIST) and decimal symbol (LOCALE_SDECIMAL), checked:
    /// a separator that is empty, more than one character, a quote, a line break, a space or a
    /// digit cannot separate fields, and one equal to the decimal symbol would split numbers.
    /// Then: the decimal symbol decides (',' gets ';', anything else ',' and '.').
    pub fn from_locale(list: &str, dec: &str) -> CsvFormat {
        let one = |s: &str| {
            let mut c = s.chars();
            match (c.next(), c.next()) {
                (Some(x), None) => Some(x),
                _ => None,
            }
        };
        let dec_ok = one(dec).filter(|c| matches!(c, '.' | ',' | '\u{066B}' | '\u{00B7}'));
        let sep_ok = one(list).filter(|c| !matches!(c, '"' | '\r' | '\n' | ' ' | '\'' | '=') && !c.is_ascii_digit() && !c.is_alphabetic() && Some(*c) != dec_ok);
        match (sep_ok, dec_ok) {
            (Some(s), Some(d)) => CsvFormat { sep: s.to_string(), dec: d.to_string() },
            (None, Some(',')) => CsvFormat { sep: ";".into(), dec: ",".into() },
            (Some(s), None) if s != '.' => CsvFormat { sep: s.to_string(), dec: ".".into() },
            _ => CsvFormat::default(),
        }
    }

    /// A field: quoted when it holds the separator, a quote, a line break or edge spaces. Text
    /// from outside (`text`) that a spreadsheet would run as a formula gets an apostrophe.
    pub fn field(&self, v: &str, text: bool) -> String {
        let mut v = v.to_string();
        if text && v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            v.insert(0, '\'');
        }
        if v.contains(self.sep.as_str()) || v.contains(['"', '\r', '\n']) || v.starts_with(' ') || v.ends_with(' ') {
            format!("\"{}\"", v.replace('"', "\"\""))
        } else {
            v
        }
    }

    /// A number with `places` decimals in the locale's decimal symbol.
    pub fn num(&self, v: f64, places: usize) -> String {
        format!("{v:.places$}").replace('.', &self.dec)
    }
}
