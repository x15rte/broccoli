//! Language-free user-visible messages: [`Diag`] pairs a [`Key`] with the
//! values its placeholders need, so code that cannot reach the active
//! [`Language`] can still hand the display boundary a complete message.
//! [`DiagError`] adds a cause chain: app-authored layers stay [`Diag`]s,
//! external causes stay verbatim text.

use crate::i18n::{Key, t_fmt};
use crate::model::settings::Language;
use std::error::Error;
use std::fmt;

/// One placeholder value: literal text, or a nested message that renders in
/// the same language as its parent. Crate-visible so the helper process can
/// serialize a message chain for the GUI to render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DiagArg {
    Text(String),
    Message(Box<Diag>),
}

/// A user-visible message that has no language yet: a key plus the values
/// its placeholders need. Code that cannot reach the active `Language`
/// carries a `Diag`; the display boundary renders it with `text`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diag {
    key: Key,
    args: Vec<DiagArg>,
}

impl Diag {
    /// A message for `key` whose placeholders have no values yet.
    pub fn new(key: Key) -> Self {
        Self {
            key,
            args: Vec::new(),
        }
    }

    /// Attach the next placeholder value, in template order.
    #[must_use]
    pub fn arg(mut self, value: impl fmt::Display) -> Self {
        self.args.push(DiagArg::Text(value.to_string()));
        self
    }

    /// Attach the next placeholder value as a nested message, so it renders
    /// in the same language as this one.
    #[must_use]
    pub fn arg_message(mut self, message: Diag) -> Self {
        self.args.push(DiagArg::Message(Box::new(message)));
        self
    }

    /// The key this message renders.
    pub fn key(&self) -> Key {
        self.key
    }

    /// The placeholder values, in template order. Crate-visible: the helper
    /// process serializes a message for the GUI instead of rendering it.
    pub(crate) fn args(&self) -> &[DiagArg] {
        &self.args
    }

    /// Render the message in `language`.
    pub fn text(&self, language: Language) -> String {
        let rendered: Vec<String> = self
            .args
            .iter()
            .map(|arg| match arg {
                DiagArg::Text(text) => text.clone(),
                DiagArg::Message(message) => message.text(language),
            })
            .collect();
        let args: Vec<&dyn fmt::Display> = rendered
            .iter()
            .map(|value| value as &dyn fmt::Display)
            .collect();
        t_fmt(language, self.key, &args)
    }
}

/// English rendering, for `Display` plumbing (logs, tests, error chains).
impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

/// A failure chain: app-authored layers render in the active language,
/// external causes (I/O, parsing) render verbatim.
#[derive(Debug)]
pub struct DiagError {
    diag: Diag,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl DiagError {
    /// A failure whose message is `diag` and whose cause is not attached yet.
    pub fn new(diag: Diag) -> Self {
        Self { diag, source: None }
    }

    /// Attach the cause below this message.
    #[must_use]
    pub fn caused_by<E: Into<Box<dyn Error + Send + Sync + 'static>>>(mut self, cause: E) -> Self {
        self.source = Some(cause.into());
        self
    }

    /// Attach a cause that is only text — external output that has no error
    /// type of its own. The text renders verbatim, like every external cause.
    #[must_use]
    pub fn caused_by_text(mut self, cause: impl Into<String>) -> Self {
        self.source = Some(Box::new(TextCause(cause.into())));
        self
    }

    /// The keyed message of this layer.
    pub fn diag(&self) -> &Diag {
        &self.diag
    }

    /// Render the whole chain in `language`, layers joined with `": "`.
    /// Layers that are themselves [`DiagError`]s render their key text;
    /// every other layer renders its own `Display` (external text stays
    /// exactly as the source produced it).
    pub fn text(&self, language: Language) -> String {
        let mut parts = vec![self.diag.text(language)];
        let mut cursor: Option<&(dyn Error + 'static)> = self.source();
        while let Some(error) = cursor {
            match error.downcast_ref::<DiagError>() {
                Some(inner) => parts.push(inner.diag.text(language)),
                None => parts.push(error.to_string()),
            }
            cursor = error.source();
        }
        parts.join(": ")
    }
}

impl fmt::Display for DiagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

/// A cause that carries text only, for external output without an error type.
#[derive(Debug)]
struct TextCause(String);

impl fmt::Display for TextCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TextCause {}

impl Error for DiagError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|error| error as &(dyn Error + 'static))
    }
}

impl From<Diag> for DiagError {
    fn from(diag: Diag) -> Self {
        Self::new(diag)
    }
}

/// Adds a keyed message to a `Result`, the way `anyhow::Context` adds text.
/// The message renders in the active language at the display boundary; the
/// cause travels unchanged.
pub trait DiagResult<T> {
    /// Wrap the error below a message for `key`.
    fn diag(self, key: Key) -> Result<T, DiagError>;
    /// Wrap the error below a pre-built message.
    fn diag_with(self, diag: Diag) -> Result<T, DiagError>;
}

impl<T, E> DiagResult<T> for Result<T, E>
where
    E: Into<Box<dyn Error + Send + Sync + 'static>>,
{
    fn diag(self, key: Key) -> Result<T, DiagError> {
        self.map_err(|cause| DiagError::new(Diag::new(key)).caused_by(cause))
    }

    fn diag_with(self, diag: Diag) -> Result<T, DiagError> {
        self.map_err(|cause| DiagError::new(diag).caused_by(cause))
    }
}

#[cfg(test)]
mod tests {
    use super::{Diag, DiagError, DiagResult};
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use std::error::Error;
    use std::io;

    #[test]
    fn nested_message_arguments_render_in_the_same_language() {
        let message =
            Diag::new(Key::LatencyFeedbackFailed).arg_message(Diag::new(Key::LatencyTimeout));
        assert_eq!(
            message.text(Language::En),
            t_fmt(
                Language::En,
                Key::LatencyFeedbackFailed,
                &[&t(Language::En, Key::LatencyTimeout)]
            )
        );
    }

    #[test]
    fn error_chain_renders_app_layers_in_the_language_and_causes_verbatim() {
        let error = DiagError::new(Diag::new(Key::CoreSetupBusy)).caused_by(
            DiagError::new(Diag::new(Key::ApplyResultFailed)).caused_by(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test",
            )),
        );
        assert_eq!(
            error.text(Language::En),
            format!(
                "{}: {}: denied by test",
                t(Language::En, Key::CoreSetupBusy),
                t(Language::En, Key::ApplyResultFailed)
            )
        );
        assert!(error.source().is_some(), "the cause stays walkable");
    }

    #[test]
    fn diag_result_attaches_the_key_and_keeps_the_cause() {
        let failed: Result<(), io::Error> = Err(io::Error::new(io::ErrorKind::NotFound, "missing"));
        let error = failed.diag(Key::ApplyResultFailed).expect_err("must fail");
        assert_eq!(error.diag().key(), Key::ApplyResultFailed);
        assert_eq!(
            error.text(Language::En),
            format!("{}: missing", t(Language::En, Key::ApplyResultFailed))
        );
    }

    #[test]
    fn display_renders_english_for_logs_and_tests() {
        let error = DiagError::new(Diag::new(Key::AppPhaseStopped));
        assert_eq!(error.to_string(), t(Language::En, Key::AppPhaseStopped));
    }
}
