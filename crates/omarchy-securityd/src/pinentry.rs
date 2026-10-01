// SPDX-License-Identifier: GPL-3.0-or-later

//! Asks the user for a passphrase with `pinentry`, speaking its Assuan
//! protocol over the program's stdin and stdout (plan §5.5).
//!
//! The passphrase lives only in [`Zeroizing`] buffers sized up front, so
//! they are never reallocated and every copy is wiped when dropped.

use std::ffi::OsString;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStdin, ChildStdout};
use zeroize::{Zeroize, Zeroizing};

/// The longest response accepted from pinentry, passphrase included.
const MAX_RESPONSE: usize = 16 * 1024;
/// pinentry gives up on its own after this long (`SETTIMEOUT`).
const PROMPT_TIMEOUT_SECS: u32 = 120;
/// The whole exchange, as a backstop if pinentry ignores `SETTIMEOUT`.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(PROMPT_TIMEOUT_SECS as u64 + 30);

/// libgpg-error codes, in the low 16 bits of an `ERR` line's code.
const GPG_ERR_TIMEOUT: u32 = 62;
const GPG_ERR_CANCELED: u32 = 99;
const GPG_ERR_ASS_CANCELED: u32 = 277;

pub struct Prompt<'a> {
    pub title: &'a str,
    pub description: &'a str,
    pub prompt: &'a str,
    /// Shown above the entry field, for a retry after a wrong passphrase.
    pub error: Option<&'a str>,
    /// For a new passphrase: the label of a second field that must match
    /// the first (`SETREPEAT`), and the error shown when it does not.
    pub repeat: Option<Repeat<'a>>,
}

pub struct Repeat<'a> {
    pub prompt: &'a str,
    pub mismatch: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    /// The user closed the dialog, or it timed out.
    Cancelled,
    Failed(String),
}

/// Runs `command` (program then arguments) and asks for one passphrase.
pub async fn get_pin(
    command: &[OsString],
    prompt: &Prompt<'_>,
) -> Result<Zeroizing<String>, PinError> {
    get_pin_repeated(command, prompt).await.map(|(pin, _)| pin)
}

/// Like [`get_pin`], and also says whether pinentry had the passphrase
/// typed twice and checked that both matched (`S PIN_REPEATED`), which
/// only happens when `prompt.repeat` is set and pinentry knows
/// `SETREPEAT`. When it did not, the caller has to ask again itself.
pub async fn get_pin_repeated(
    command: &[OsString],
    prompt: &Prompt<'_>,
) -> Result<(Zeroizing<String>, bool), PinError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| PinError::Failed("no pinentry program configured".into()))?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| PinError::Failed(format!("starting {}: {e}", program.to_string_lossy())))?;
    let mut session = Session {
        stdin: child.stdin.take().expect("piped stdin"),
        stdout: child.stdout.take().expect("piped stdout"),
        buf: Zeroizing::new(Vec::with_capacity(MAX_RESPONSE)),
        repeated: false,
    };
    let result = tokio::time::timeout(EXCHANGE_TIMEOUT, session.exchange(prompt))
        .await
        .unwrap_or(Err(PinError::Cancelled));
    drop(session);
    // Closing its stdin ends pinentry; kill it if it lingers.
    if tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
    result
}

struct Session {
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Bytes read but not yet consumed as lines.
    buf: Zeroizing<Vec<u8>>,
    /// pinentry sent `S PIN_REPEATED`.
    repeated: bool,
}

impl Session {
    async fn exchange(
        &mut self,
        prompt: &Prompt<'_>,
    ) -> Result<(Zeroizing<String>, bool), PinError> {
        self.response(None).await?;
        let mut commands = vec![
            format!("SETTITLE {}", escape(prompt.title)),
            format!("SETDESC {}", escape(prompt.description)),
            format!("SETPROMPT {}", escape(prompt.prompt)),
        ];
        if let Some(error) = prompt.error {
            commands.push(format!("SETERROR {}", escape(error)));
        }
        for command in commands {
            self.send(&command).await?;
            self.response(None).await?;
        }
        // Older pinentries do not know SETTIMEOUT or SETREPEAT; that is not
        // an error.
        let mut optional = vec![format!("SETTIMEOUT {PROMPT_TIMEOUT_SECS}")];
        if let Some(repeat) = &prompt.repeat {
            optional.push(format!("SETREPEATERROR {}", escape(repeat.mismatch)));
            optional.push(format!("SETREPEAT {}", escape(repeat.prompt)));
        }
        for command in optional {
            self.send(&command).await?;
            let _ = self.response(None).await;
        }

        self.send("GETPIN").await?;
        let mut pin = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE));
        self.response(Some(&mut pin)).await?;
        let _ = self.send("BYE").await;
        let bytes = std::mem::take(&mut *pin);
        let pin = String::from_utf8(bytes)
            .map(Zeroizing::new)
            .map_err(|err| {
                err.into_bytes().zeroize();
                PinError::Failed("the passphrase is not valid UTF-8".into())
            })?;
        Ok((pin, self.repeated))
    }

    async fn send(&mut self, line: &str) -> Result<(), PinError> {
        let mut line = line.as_bytes().to_vec();
        line.push(b'\n');
        self.stdin
            .write_all(&line)
            .await
            .map_err(|e| PinError::Failed(format!("writing to pinentry: {e}")))
    }

    /// Reads lines up to the `OK` or `ERR` that ends a response, decoding
    /// `D` lines into `data`.
    async fn response(&mut self, mut data: Option<&mut Vec<u8>>) -> Result<(), PinError> {
        loop {
            let Some(end) = self.buf.iter().position(|&b| b == b'\n') else {
                self.fill().await?;
                continue;
            };
            let outcome = {
                let line = &self.buf[..end];
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line == b"S PIN_REPEATED" || line.starts_with(b"S PIN_REPEATED ") {
                    self.repeated = true;
                }
                classify(line, data.as_deref_mut())
            };
            self.buf.drain(..=end);
            match outcome? {
                Line::Done => return Ok(()),
                Line::Inquire => self.send("END").await?,
                Line::More => {}
            }
        }
    }

    async fn fill(&mut self) -> Result<(), PinError> {
        let mut chunk = Zeroizing::new([0u8; 1024]);
        let n = self
            .stdout
            .read(&mut chunk[..])
            .await
            .map_err(|e| PinError::Failed(format!("reading from pinentry: {e}")))?;
        if n == 0 {
            return Err(PinError::Failed("pinentry exited unexpectedly".into()));
        }
        if self.buf.len() + n > self.buf.capacity() {
            return Err(PinError::Failed("pinentry response is too long".into()));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }
}

enum Line {
    Done,
    Inquire,
    More,
}

fn classify(line: &[u8], data: Option<&mut Vec<u8>>) -> Result<Line, PinError> {
    if line == b"OK" || line.starts_with(b"OK ") {
        return Ok(Line::Done);
    }
    if let Some(rest) = line.strip_prefix(b"ERR ") {
        let text = String::from_utf8_lossy(rest);
        let (code, message) = text.split_once(' ').unwrap_or((&text, ""));
        let code: u32 = code.parse().unwrap_or(0);
        return Err(match code & 0xffff {
            GPG_ERR_CANCELED | GPG_ERR_ASS_CANCELED | GPG_ERR_TIMEOUT => PinError::Cancelled,
            _ => PinError::Failed(format!("pinentry: {message} ({code})")),
        });
    }
    if let Some(rest) = line.strip_prefix(b"D ") {
        if let Some(data) = data {
            unescape_into(rest, data)?;
        }
        return Ok(Line::More);
    }
    if line.starts_with(b"INQUIRE ") {
        return Ok(Line::Inquire);
    }
    // Status (`S`) and comment (`#`) lines.
    Ok(Line::More)
}

/// Percent-escapes what an Assuan parameter may not contain.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            c => out.push(c),
        }
    }
    out
}

/// Decodes the `%XX` escapes of a `D` line, appending to `out` without
/// reallocating it.
fn unescape_into(data: &[u8], out: &mut Vec<u8>) -> Result<(), PinError> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < data.len() {
        let byte = match data[i] {
            b'%' => {
                let decoded = data
                    .get(i + 1..i + 3)
                    .and_then(|h| Some(hex(h[0])? << 4 | hex(h[1])?))
                    .ok_or_else(|| PinError::Failed("bad escape in pinentry data".into()))?;
                i += 3;
                decoded
            }
            b => {
                i += 1;
                b
            }
        };
        if out.len() == out.capacity() {
            return Err(PinError::Failed("passphrase is too long".into()));
        }
        out.push(byte);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fake pinentry, run with `sh`. It answers `GETPIN` with `pin`, or
    /// with `retry_pin` when the caller sent `SETERROR` first; `CANCEL`
    /// cancels, and `HANG` never answers. Every command it receives is
    /// appended to `log`. It ignores `SETREPEAT`, as an old pinentry does.
    pub fn fake(dir: &std::path::Path, pin: &str, retry_pin: &str) -> Vec<OsString> {
        fake_with(dir, pin, retry_pin, false)
    }

    /// [`fake`], but one that knows `SETREPEAT`: after it, `GETPIN` also
    /// sends `S PIN_REPEATED`.
    pub fn fake_repeating(dir: &std::path::Path, pin: &str) -> Vec<OsString> {
        fake_with(dir, pin, pin, true)
    }

    /// A fake pinentry that answers each `GETPIN` with the next of `pins`,
    /// for the passphrase and its confirmation.
    pub fn fake_sequence(dir: &std::path::Path, pins: &[&str]) -> Vec<OsString> {
        let counter = dir.join("pinentry.count");
        let _ = std::fs::remove_file(&counter);
        let script = dir.join("pinentry-seq.sh");
        let cases: String = pins
            .iter()
            .enumerate()
            .map(|(i, pin)| format!("    {i}) pin='{pin}' ;;\n"))
            .collect();
        std::fs::write(
            &script,
            format!(
                r#"echo "OK Pleased to meet you"
while read -r cmd rest; do
  echo "$cmd $rest" >> '{log}'
  case "$cmd" in
    GETPIN)
      n=$(cat '{counter}' 2>/dev/null || echo 0); echo $((n + 1)) > '{counter}'
      case "$n" in
{cases}    *) pin=CANCEL ;;
      esac
      if [ "$pin" = CANCEL ]; then echo "ERR 83886179 Operation cancelled <Pinentry>"
      else echo "D $pin"; echo OK; fi ;;
    BYE) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
"#,
                log = dir.join("pinentry.log").display(),
                counter = counter.display(),
            ),
        )
        .unwrap();
        vec!["/bin/sh".into(), script.into()]
    }

    fn fake_with(
        dir: &std::path::Path,
        pin: &str,
        retry_pin: &str,
        repeating: bool,
    ) -> Vec<OsString> {
        let script = dir.join("pinentry.sh");
        let log = dir.join("pinentry.log");
        std::fs::write(
            &script,
            format!(
                r#"echo "OK Pleased to meet you"
retry=
repeat=
while read -r cmd rest; do
  echo "$cmd $rest" >> '{log}'
  case "$cmd" in
    SETERROR) retry=1; echo OK ;;
    SETREPEAT) if [ -n '{repeating}' ]; then repeat=1; echo OK; else echo "ERR 536871187 Unknown IPC command"; fi ;;
    GETPIN)
      if [ -n "$retry" ]; then pin='{retry_pin}'; else pin='{pin}'; fi
      if [ "$pin" = HANG ]; then exec sleep 60; fi
      if [ "$pin" = CANCEL ]; then echo "ERR 83886179 Operation cancelled <Pinentry>"
      else echo "S SOMETHING"; [ -n "$repeat" ] && echo "S PIN_REPEATED"; echo "D $pin"; echo OK; fi ;;
    BYE) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
"#,
                log = log.display(),
                repeating = if repeating { "1" } else { "" },
            ),
        )
        .unwrap();
        vec!["/bin/sh".into(), script.into()]
    }

    fn prompt(error: Option<&str>) -> Prompt<'_> {
        Prompt {
            title: "Title",
            description: "Unlock 100%\nnow",
            prompt: "Passphrase:",
            error,
            repeat: None,
        }
    }

    #[tokio::test]
    async fn asks_for_a_repeat_when_pinentry_can() {
        let dir = tempfile::tempdir().unwrap();
        let new = Prompt {
            repeat: Some(Repeat {
                prompt: "Repeat:",
                mismatch: "No match",
            }),
            ..prompt(None)
        };
        let command = fake_repeating(dir.path(), "secret");
        let (pin, repeated) = get_pin_repeated(&command, &new).await.unwrap();
        assert_eq!((pin.as_str(), repeated), ("secret", true));
        let log = std::fs::read_to_string(dir.path().join("pinentry.log")).unwrap();
        assert!(log.contains("SETREPEAT Repeat:"), "{log}");
        assert!(log.contains("SETREPEATERROR No match"), "{log}");

        // An old pinentry refuses SETREPEAT: the passphrase still comes,
        // unconfirmed.
        let command = fake(dir.path(), "secret", "unused");
        let (pin, repeated) = get_pin_repeated(&command, &new).await.unwrap();
        assert_eq!((pin.as_str(), repeated), ("secret", false));
        // Without `repeat`, no confirmation is asked for.
        let command = fake_repeating(dir.path(), "secret");
        let (_, repeated) = get_pin_repeated(&command, &prompt(None)).await.unwrap();
        assert!(!repeated);
    }

    #[tokio::test]
    async fn reads_and_decodes_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let command = fake(dir.path(), "s%25cr%0Aet+", "unused");
        let pin = get_pin(&command, &prompt(None)).await.unwrap();
        assert_eq!(pin.as_str(), "s%cr\net+");
        let log = std::fs::read_to_string(dir.path().join("pinentry.log")).unwrap();
        assert!(log.contains("SETDESC Unlock 100%25%0Anow"), "{log}");
        assert!(log.contains("GETPIN"), "{log}");
        assert!(!log.contains("SETERROR"), "{log}");

        let pin = get_pin(&command, &prompt(Some("Wrong"))).await.unwrap();
        assert_eq!(pin.as_str(), "unused");
    }

    #[tokio::test]
    async fn reports_cancel_and_failures() {
        let dir = tempfile::tempdir().unwrap();
        let command = fake(dir.path(), "CANCEL", "CANCEL");
        assert_eq!(
            get_pin(&command, &prompt(None)).await.unwrap_err(),
            PinError::Cancelled
        );
        let err = get_pin(&["/nonexistent/pinentry".into()], &prompt(None))
            .await
            .unwrap_err();
        assert!(matches!(err, PinError::Failed(m) if m.contains("starting")));
        let err = get_pin(&["/bin/true".into()], &prompt(None))
            .await
            .unwrap_err();
        assert!(matches!(err, PinError::Failed(m) if m.contains("exited")));
    }

    #[test]
    fn unescape_rejects_bad_escapes_and_overflow() {
        let mut out = Vec::with_capacity(4);
        assert!(unescape_into(b"%4", &mut out).is_err());
        let mut out = Vec::with_capacity(4);
        assert!(unescape_into(b"%zz", &mut out).is_err());
        let mut out = Vec::with_capacity(2);
        assert!(unescape_into(b"abc", &mut out).is_err());
        let mut out = Vec::with_capacity(4);
        unescape_into(b"a%41", &mut out).unwrap();
        assert_eq!(out, b"aA");
    }
}
