use std::{error::Error, fmt, io};

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use dtx_security::SecretBytes;
use dtx_wire::StableCode;
use zeroize::Zeroizing;

/// Minimum synthetic canary length, chosen to avoid common short-string false positives.
pub const MIN_CANARY_BYTES: usize = 32;

/// Output boundary scanned for synthetic secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    Log,
    Trace,
    Golden,
    CrashDump,
    Analytics,
    Push,
    DiagnosticBundle,
}

impl ArtifactKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Trace => "trace",
            Self::Golden => "golden artifact",
            Self::CrashDump => "crash dump",
            Self::Analytics => "analytics artifact",
            Self::Push => "push payload",
            Self::DiagnosticBundle => "diagnostic bundle",
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Supported representation of one synthetic secret canary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryRepresentation {
    Raw,
    HexLower,
    HexUpper,
    Base64StandardPadded,
    Base64StandardUnpadded,
    Base64UrlPadded,
    Base64UrlUnpadded,
}

impl CanaryRepresentation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::HexLower => "lowercase hexadecimal",
            Self::HexUpper => "uppercase hexadecimal",
            Self::Base64StandardPadded => "padded standard base64",
            Self::Base64StandardUnpadded => "unpadded standard base64",
            Self::Base64UrlPadded => "padded URL-safe base64",
            Self::Base64UrlUnpadded => "unpadded URL-safe base64",
        }
    }
}

impl fmt::Display for CanaryRepresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

struct CanaryPattern {
    label: StableCode,
    representation: CanaryRepresentation,
    bytes: Zeroizing<Vec<u8>>,
}

/// Scanner for raw and commonly encoded representations of synthetic secrets.
pub struct CanaryScanner {
    patterns: Vec<CanaryPattern>,
    max_pattern_len: usize,
}

impl CanaryScanner {
    /// Builds a scanner and consumes all supplied synthetic secrets.
    ///
    /// # Errors
    ///
    /// Rejects an empty set or any canary shorter than [`MIN_CANARY_BYTES`].
    pub fn new(
        canaries: impl IntoIterator<Item = (StableCode, SecretBytes)>,
    ) -> Result<Self, CanaryConfigError> {
        let mut patterns = Vec::new();
        let mut count = 0_usize;
        for (label, secret) in canaries {
            count += 1;
            if secret.len() < MIN_CANARY_BYTES {
                return Err(CanaryConfigError::TooShort { label });
            }
            secret.expose(|bytes| add_representations(&mut patterns, &label, bytes));
        }
        if count == 0 {
            return Err(CanaryConfigError::EmptySet);
        }
        let max_pattern_len = patterns
            .iter()
            .map(|pattern| pattern.bytes.len())
            .max()
            .unwrap_or(0);
        Ok(Self {
            patterns,
            max_pattern_len,
        })
    }

    /// Scans exact bytes without interpreting the artifact as UTF-8.
    ///
    /// # Errors
    ///
    /// Returns redacted leak metadata for the first matching canary representation.
    pub fn scan_bytes(
        &self,
        artifact_kind: ArtifactKind,
        artifact: &[u8],
    ) -> Result<(), CanaryLeak> {
        for pattern in &self.patterns {
            if contains_subslice(artifact, pattern.bytes.as_slice()) {
                return Err(CanaryLeak {
                    label: pattern.label.clone(),
                    artifact_kind,
                    representation: pattern.representation,
                });
            }
        }
        Ok(())
    }

    const fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }
}

/// Invalid synthetic-canary configuration. No secret bytes are retained in the error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanaryConfigError {
    EmptySet,
    TooShort { label: StableCode },
}

impl fmt::Display for CanaryConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySet => formatter.write_str("at least one synthetic canary is required"),
            Self::TooShort { label } => write!(
                formatter,
                "synthetic canary {label} is shorter than {MIN_CANARY_BYTES} bytes"
            ),
        }
    }
}

impl Error for CanaryConfigError {}

/// Redacted evidence that a synthetic secret reached a forbidden artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryLeak {
    label: StableCode,
    artifact_kind: ArtifactKind,
    representation: CanaryRepresentation,
}

impl CanaryLeak {
    #[must_use]
    pub const fn label(&self) -> &StableCode {
        &self.label
    }

    #[must_use]
    pub const fn artifact_kind(&self) -> ArtifactKind {
        self.artifact_kind
    }

    #[must_use]
    pub const fn representation(&self) -> CanaryRepresentation {
        self.representation
    }
}

impl fmt::Display for CanaryLeak {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "synthetic canary {} detected in {} as {}",
            self.label, self.artifact_kind, self.representation
        )
    }
}

impl Error for CanaryLeak {}

/// A scanning writer that withholds enough trailing bytes to detect cross-write canaries.
pub struct CanaryWriter<'scanner, W> {
    inner: W,
    scanner: &'scanner CanaryScanner,
    artifact_kind: ArtifactKind,
    tail: Zeroizing<Vec<u8>>,
    violation: Option<CanaryLeak>,
}

impl<'scanner, W> CanaryWriter<'scanner, W> {
    #[must_use]
    pub fn new(inner: W, scanner: &'scanner CanaryScanner, artifact_kind: ArtifactKind) -> Self {
        Self {
            inner,
            scanner,
            artifact_kind,
            tail: Zeroizing::new(Vec::new()),
            violation: None,
        }
    }

    #[must_use]
    pub const fn violation(&self) -> Option<&CanaryLeak> {
        self.violation.as_ref()
    }
}

impl<W: io::Write> CanaryWriter<'_, W> {
    /// Flushes the final clean withheld tail and returns the wrapped writer.
    ///
    /// # Errors
    ///
    /// Returns a redacted I/O error after a leak or when the wrapped writer fails.
    pub fn finish(mut self) -> io::Result<W> {
        if let Some(leak) = &self.violation {
            return Err(leak_io_error(leak));
        }
        self.inner.write_all(self.tail.as_slice())?;
        self.tail.clear();
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: io::Write> io::Write for CanaryWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if let Some(leak) = &self.violation {
            return Err(leak_io_error(leak));
        }

        let mut combined = Zeroizing::new(Vec::with_capacity(self.tail.len() + buffer.len()));
        combined.extend_from_slice(self.tail.as_slice());
        combined.extend_from_slice(buffer);
        if let Err(leak) = self
            .scanner
            .scan_bytes(self.artifact_kind, combined.as_slice())
        {
            let error = leak_io_error(&leak);
            self.violation = Some(leak);
            return Err(error);
        }

        let retained = self
            .scanner
            .max_pattern_len()
            .saturating_sub(1)
            .min(combined.len());
        let safe_len = combined.len() - retained;
        self.inner.write_all(&combined[..safe_len])?;
        self.tail.clear();
        self.tail.extend_from_slice(&combined[safe_len..]);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(leak) = &self.violation {
            return Err(leak_io_error(leak));
        }
        self.inner.flush()
    }
}

fn add_representations(patterns: &mut Vec<CanaryPattern>, label: &StableCode, raw: &[u8]) {
    add_pattern(patterns, label, CanaryRepresentation::Raw, raw.to_vec());
    add_pattern(
        patterns,
        label,
        CanaryRepresentation::HexLower,
        encode_hex(raw, false),
    );
    add_pattern(
        patterns,
        label,
        CanaryRepresentation::HexUpper,
        encode_hex(raw, true),
    );
    add_pattern(
        patterns,
        label,
        CanaryRepresentation::Base64StandardPadded,
        Base64::encode_string(raw).into_bytes(),
    );
    add_pattern(
        patterns,
        label,
        CanaryRepresentation::Base64StandardUnpadded,
        Base64Unpadded::encode_string(raw).into_bytes(),
    );
    add_pattern(
        patterns,
        label,
        CanaryRepresentation::Base64UrlPadded,
        Base64Url::encode_string(raw).into_bytes(),
    );
    add_pattern(
        patterns,
        label,
        CanaryRepresentation::Base64UrlUnpadded,
        Base64UrlUnpadded::encode_string(raw).into_bytes(),
    );
}

fn add_pattern(
    patterns: &mut Vec<CanaryPattern>,
    label: &StableCode,
    representation: CanaryRepresentation,
    bytes: Vec<u8>,
) {
    if patterns
        .iter()
        .any(|pattern| pattern.label == *label && pattern.bytes.as_slice() == bytes)
    {
        return;
    }
    patterns.push(CanaryPattern {
        label: label.clone(),
        representation,
        bytes: Zeroizing::new(bytes),
    });
}

fn encode_hex(value: &[u8], uppercase: bool) -> Vec<u8> {
    let alphabet = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut output = Vec::with_capacity(value.len() * 2);
    for byte in value {
        output.push(alphabet[usize::from(byte >> 4)]);
        output.push(alphabet[usize::from(byte & 0x0f)]);
    }
    output
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn leak_io_error(leak: &CanaryLeak) -> io::Error {
    io::Error::other(leak.to_string())
}
