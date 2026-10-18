//! Terminal modes in PTY output (PROTOCOL.md §15.11): the few modes full-screen
//! programs switch, followed so that a new Attachment can set them in its terminal
//! and a Client can reset them when its Attachment ends early. Only these switches
//! are followed; no screen state is kept.

use std::collections::BTreeSet;

/// DEC private modes followed (`CSI ? Pm h` / `CSI ? Pm l`), all off by default
/// except cursor visibility (25).
const FOLLOWED: [u16; 14] = [
    1,    // cursor keys in application mode
    9,    // mouse: X10
    25,   // cursor visible
    47,   // alternate screen
    1000, // mouse: press and release
    1002, // mouse: motion while pressed
    1003, // mouse: all motion
    1004, // focus events
    1005, // mouse: UTF-8 coordinates
    1006, // mouse: SGR coordinates
    1015, // mouse: urxvt coordinates
    1047, // alternate screen
    1049, // alternate screen, saving the cursor
    2004, // bracketed paste
];

const CURSOR_VISIBLE: u16 = 25;

/// Longest parameter list followed; longer sequences are ignored.
const MAX_PARAMETERS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parser {
    Ground,
    Escape,
    Csi,
    PrivateCsi,
}

#[derive(Debug, Clone)]
pub struct Modes {
    /// Followed modes not at their default: set ones, and 25 when the cursor is hidden.
    changed: BTreeSet<u16>,
    /// Keypad in application mode (`ESC =`).
    keypad: bool,
    parser: Parser,
    parameters: String,
}

impl Default for Modes {
    fn default() -> Self {
        Self::new()
    }
}

impl Modes {
    pub fn new() -> Self {
        Self {
            changed: BTreeSet::new(),
            keypad: false,
            parser: Parser::Ground,
            parameters: String::new(),
        }
    }

    /// Follows the mode switches in a piece of output; sequences may be split over
    /// pieces.
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            self.parser = match (self.parser, byte) {
                (_, 0x1b) => Parser::Escape,
                (Parser::Ground, _) => Parser::Ground,
                (Parser::Escape, b'[') => {
                    self.parameters.clear();
                    Parser::Csi
                }
                (Parser::Escape, b'=') => {
                    self.keypad = true;
                    Parser::Ground
                }
                (Parser::Escape, b'>') => {
                    self.keypad = false;
                    Parser::Ground
                }
                (Parser::Escape, _) => Parser::Ground,
                (Parser::Csi, b'?') if self.parameters.is_empty() => Parser::PrivateCsi,
                (Parser::Csi, 0x40..=0x7e) => Parser::Ground,
                (Parser::Csi, _) => Parser::Csi,
                (Parser::PrivateCsi, b'0'..=b'9' | b';') => {
                    if self.parameters.len() < MAX_PARAMETERS {
                        self.parameters.push(byte as char);
                    }
                    Parser::PrivateCsi
                }
                (Parser::PrivateCsi, b'h' | b'l') => {
                    self.switch(byte == b'h');
                    Parser::Ground
                }
                (Parser::PrivateCsi, _) => Parser::Ground,
            };
        }
    }

    fn switch(&mut self, set: bool) {
        if self.parameters.len() >= MAX_PARAMETERS {
            return;
        }
        for mode in self
            .parameters
            .split(';')
            .filter_map(|p| p.parse::<u16>().ok())
        {
            if !FOLLOWED.contains(&mode) {
                continue;
            }
            // Cursor visibility is on by default: hiding it is the change.
            let changed = if mode == CURSOR_VISIBLE { !set } else { set };
            if changed {
                self.changed.insert(mode);
            } else {
                self.changed.remove(&mode);
            }
        }
    }

    /// The sequence that sets the followed modes as they are now, in a terminal in
    /// its default state; empty if all are at their default.
    // Used by the Server, which runs on Unix only for now (gate G2).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn restore(&self) -> Vec<u8> {
        let mut out = String::new();
        for &mode in &self.changed {
            let set = if mode == CURSOR_VISIBLE { 'l' } else { 'h' };
            out.push_str(&format!("\x1b[?{mode}{set}"));
        }
        if self.keypad {
            out.push_str("\x1b=");
        }
        out.into_bytes()
    }

    /// The sequence that returns the followed modes to their defaults, leaving an
    /// alternate screen first; empty if all are at their default.
    pub fn reset(&self) -> Vec<u8> {
        let mut out = String::new();
        for &mode in self.changed.iter().rev() {
            let reset = if mode == CURSOR_VISIBLE { 'h' } else { 'l' };
            out.push_str(&format!("\x1b[?{mode}{reset}"));
        }
        if self.keypad {
            out.push_str("\x1b>");
        }
        out.into_bytes()
    }

    /// Whether an alternate screen is active.
    #[cfg(test)]
    pub fn alternate_screen(&self) -> bool {
        [47, 1047, 1049].iter().any(|m| self.changed.contains(m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn follows_switches_split_over_pieces() {
        let mut modes = Modes::new();
        // Like htop at its start: alternate screen, keypad, hidden cursor, mouse.
        modes.feed(b"\x1b[?1049h\x1b[22;0;0t\x1b[1;24r\x1b(B\x1b[m\x1b[4l\x1b[?7h\x1b=\x1b[?");
        modes.feed(b"25l\x1b[?1000;1006h");
        assert!(modes.alternate_screen());
        assert_eq!(
            text(modes.restore()),
            "\x1b[?25l\x1b[?1000h\x1b[?1006h\x1b[?1049h\x1b="
        );
        assert_eq!(
            text(modes.reset()),
            "\x1b[?1049l\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b>"
        );
        // Leaving restores the defaults.
        modes.feed(b"\x1b[?1000;1006l\x1b[?25h\x1b[?1049l\x1b>");
        assert!(modes.restore().is_empty());
        assert!(modes.reset().is_empty());
        assert!(!modes.alternate_screen());
    }

    #[test]
    fn ignores_other_sequences() {
        let mut modes = Modes::new();
        // Mode 7 is not followed; a non-private CSI h (insert mode) is not a DEC mode;
        // an OSC with ESC \ ends normally.
        modes.feed(b"\x1b[?7l\x1b[4h\x1b]0;title\x1b\\\x1b[?12;25l");
        assert_eq!(text(modes.restore()), "\x1b[?25l");
        let long = format!("\x1b[?{}1049h", "1;".repeat(40));
        let mut modes = Modes::new();
        modes.feed(long.as_bytes());
        assert!(modes.restore().is_empty());
    }
}
