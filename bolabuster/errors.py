"""Exception-Hierarchie fuer bolabuster."""


class BolabusterError(Exception):
    """Basisklasse aller bolabuster-spezifischen Fehler."""


class ConfigError(BolabusterError):
    """Fehler beim Laden oder Validieren der Identitaets-/Scope-Config."""


class CorpusParseError(BolabusterError):
    """Ein Corpus-Parser konnte eine Quelle nicht verarbeiten."""

    def __init__(self, source: str, reason: str) -> None:
        self.source = source
        self.reason = reason
        super().__init__(f"failed to parse corpus source {source!r}: {reason}")

    def __str__(self) -> str:
        return f"failed to parse corpus source {self.source!r}: {self.reason}"


class UnsupportedCorpusError(BolabusterError):
    """Das Corpus-Format wird von keinem registrierten Parser unterstuetzt."""


class AmbiguousCorpusError(BolabusterError):
    """Mehrere Parser fuehlen sich fuer dieselbe Quelle zustaendig."""


class ReportWriteError(BolabusterError):
    """Ein Report konnte nicht geschrieben werden."""
