"""
Security function database for taint-aware context injection.

Curated catalog of known sources, sinks, and sanitizers across Python, JS/TS, and Go.
Used by context.py to classify imported functions for budget prioritization and
source/sink annotation in scan output.
"""

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class SecurityFunction:
    name: str
    module: str
    kind: Literal["source", "sink", "sanitizer"]
    language: str
    cwe: list[int] = field(default_factory=list)


SECURITY_DB: list[SecurityFunction] = [
    # =========================================================================
    # PYTHON — Sinks
    # =========================================================================
    SecurityFunction("execute", "sqlite3.Cursor", "sink", "python", [89]),
    SecurityFunction("executemany", "sqlite3.Cursor", "sink", "python", [89]),
    SecurityFunction("executescript", "sqlite3.Connection", "sink", "python", [89]),
    SecurityFunction("execute", "psycopg2.cursor", "sink", "python", [89]),
    SecurityFunction("execute", "pymysql.cursors", "sink", "python", [89]),
    SecurityFunction("raw", "django.db.models.Manager", "sink", "python", [89]),
    SecurityFunction("extra", "django.db.models.QuerySet", "sink", "python", [89]),
    SecurityFunction("run", "subprocess", "sink", "python", [78]),
    SecurityFunction("call", "subprocess", "sink", "python", [78]),
    SecurityFunction("Popen", "subprocess", "sink", "python", [78]),
    SecurityFunction("check_output", "subprocess", "sink", "python", [78]),
    SecurityFunction("check_call", "subprocess", "sink", "python", [78]),
    SecurityFunction("system", "os", "sink", "python", [78]),
    SecurityFunction("popen", "os", "sink", "python", [78]),
    SecurityFunction("exec", "builtins", "sink", "python", [94, 95]),
    SecurityFunction("eval", "builtins", "sink", "python", [94, 95]),
    SecurityFunction("compile", "builtins", "sink", "python", [94]),
    SecurityFunction("open", "builtins", "sink", "python", [22, 73]),
    SecurityFunction("makedirs", "os", "sink", "python", [22]),
    SecurityFunction("rename", "os", "sink", "python", [73]),
    SecurityFunction("remove", "os", "sink", "python", [22]),
    SecurityFunction("unlink", "os", "sink", "python", [22]),
    SecurityFunction("write", "io.FileIO", "sink", "python", [22]),
    SecurityFunction("send", "smtplib.SMTP", "sink", "python", [93]),
    SecurityFunction("urlopen", "urllib.request", "sink", "python", [918]),
    SecurityFunction("get", "requests", "sink", "python", [918]),
    SecurityFunction("post", "requests", "sink", "python", [918]),
    SecurityFunction("request", "httpx.Client", "sink", "python", [918]),
    SecurityFunction("render_template_string", "flask", "sink", "python", [79]),
    SecurityFunction("Markup", "markupsafe", "sink", "python", [79]),
    SecurityFunction("format_html", "django.utils.html", "sink", "python", [79]),
    SecurityFunction("deserialize", "yaml", "sink", "python", [502]),
    SecurityFunction("load", "yaml", "sink", "python", [502]),
    SecurityFunction("loads", "pickle", "sink", "python", [502]),
    SecurityFunction("load", "pickle", "sink", "python", [502]),
    SecurityFunction("loads", "marshal", "sink", "python", [502]),
    SecurityFunction("redirect", "flask", "sink", "python", [601]),
    SecurityFunction("HttpResponseRedirect", "django.http", "sink", "python", [601]),
    # =========================================================================
    # PYTHON — Sources
    # =========================================================================
    SecurityFunction("input", "builtins", "source", "python", [20]),
    SecurityFunction("argv", "sys", "source", "python", [78, 89]),
    SecurityFunction("environ", "os", "source", "python", [78, 89]),
    SecurityFunction("getenv", "os", "source", "python", [78, 89]),
    SecurityFunction("read", "sys.stdin", "source", "python", [20]),
    SecurityFunction("request.form", "flask", "source", "python", [89, 79]),
    SecurityFunction("request.args", "flask", "source", "python", [89, 79]),
    SecurityFunction("request.json", "flask", "source", "python", [89, 79]),
    SecurityFunction("request.data", "flask", "source", "python", [89, 79]),
    SecurityFunction("request.cookies", "flask", "source", "python", [20]),
    SecurityFunction("request.headers", "flask", "source", "python", [20]),
    SecurityFunction("request.GET", "django.http", "source", "python", [89, 79]),
    SecurityFunction("request.POST", "django.http", "source", "python", [89, 79]),
    SecurityFunction("request.body", "django.http", "source", "python", [89, 79]),
    SecurityFunction("recv", "socket.socket", "source", "python", [20]),
    SecurityFunction("read", "io.BufferedReader", "source", "python", [20]),
    SecurityFunction("urlopen", "urllib.request.response", "source", "python", [918]),
    # =========================================================================
    # PYTHON — Sanitizers
    # =========================================================================
    SecurityFunction("escape", "html", "sanitizer", "python", [79]),
    SecurityFunction("quote", "shlex", "sanitizer", "python", [78]),
    SecurityFunction("escape", "re", "sanitizer", "python", [89]),
    SecurityFunction("parameterize", "psycopg2.sql", "sanitizer", "python", [89]),
    SecurityFunction("quote_ident", "psycopg2.extensions", "sanitizer", "python", [89]),
    SecurityFunction("escape_string", "pymysql", "sanitizer", "python", [89]),
    SecurityFunction("mark_safe", "django.utils.safestring", "sanitizer", "python", [79]),
    SecurityFunction("bleach.clean", "bleach", "sanitizer", "python", [79]),
    SecurityFunction("secure_filename", "werkzeug.utils", "sanitizer", "python", [22]),
    SecurityFunction("abspath", "os.path", "sanitizer", "python", [22]),
    SecurityFunction("realpath", "os.path", "sanitizer", "python", [22]),
    # =========================================================================
    # JAVASCRIPT/TYPESCRIPT — Sinks
    # =========================================================================
    SecurityFunction("exec", "child_process", "sink", "javascript", [78]),
    SecurityFunction("execSync", "child_process", "sink", "javascript", [78]),
    SecurityFunction("spawn", "child_process", "sink", "javascript", [78]),
    SecurityFunction("execFile", "child_process", "sink", "javascript", [78]),
    SecurityFunction("eval", "global", "sink", "javascript", [94, 95]),
    SecurityFunction("Function", "global", "sink", "javascript", [94]),
    SecurityFunction("setTimeout", "global", "sink", "javascript", [94]),
    SecurityFunction("setInterval", "global", "sink", "javascript", [94]),
    SecurityFunction("innerHTML", "Element", "sink", "javascript", [79]),
    SecurityFunction("outerHTML", "Element", "sink", "javascript", [79]),
    SecurityFunction("insertAdjacentHTML", "Element", "sink", "javascript", [79]),
    SecurityFunction("document.write", "document", "sink", "javascript", [79]),
    SecurityFunction("document.writeln", "document", "sink", "javascript", [79]),
    SecurityFunction("query", "mysql", "sink", "javascript", [89]),
    SecurityFunction("raw", "knex", "sink", "javascript", [89]),
    SecurityFunction("$queryRaw", "prisma", "sink", "javascript", [89]),
    SecurityFunction("$executeRaw", "prisma", "sink", "javascript", [89]),
    SecurityFunction("serialize", "node-serialize", "sink", "javascript", [502]),
    SecurityFunction("writeFile", "fs", "sink", "javascript", [22]),
    SecurityFunction("writeFileSync", "fs", "sink", "javascript", [22]),
    SecurityFunction("createWriteStream", "fs", "sink", "javascript", [22]),
    SecurityFunction("redirect", "express.Response", "sink", "javascript", [601]),
    SecurityFunction("send", "express.Response", "sink", "javascript", [79]),
    SecurityFunction("render", "express.Response", "sink", "javascript", [79]),
    SecurityFunction("fetch", "global", "sink", "javascript", [918]),
    SecurityFunction("request", "http", "sink", "javascript", [918]),
    SecurityFunction("get", "axios", "sink", "javascript", [918]),
    SecurityFunction("post", "axios", "sink", "javascript", [918]),
    # =========================================================================
    # JAVASCRIPT/TYPESCRIPT — Sources
    # =========================================================================
    SecurityFunction("req.body", "express", "source", "javascript", [89, 79]),
    SecurityFunction("req.params", "express", "source", "javascript", [89, 79]),
    SecurityFunction("req.query", "express", "source", "javascript", [89, 79]),
    SecurityFunction("req.headers", "express", "source", "javascript", [20]),
    SecurityFunction("req.cookies", "express", "source", "javascript", [20]),
    SecurityFunction("process.env", "process", "source", "javascript", [78, 89]),
    SecurityFunction("process.argv", "process", "source", "javascript", [78]),
    SecurityFunction("readFileSync", "fs", "source", "javascript", [22]),
    SecurityFunction("createReadStream", "fs", "source", "javascript", [22]),
    SecurityFunction("URLSearchParams", "url", "source", "javascript", [89]),
    SecurityFunction("location.search", "window", "source", "javascript", [79]),
    SecurityFunction("location.hash", "window", "source", "javascript", [79]),
    SecurityFunction("document.cookie", "document", "source", "javascript", [20]),
    # =========================================================================
    # JAVASCRIPT/TYPESCRIPT — Sanitizers
    # =========================================================================
    SecurityFunction("escape", "lodash", "sanitizer", "javascript", [79]),
    SecurityFunction("escapeHtml", "escape-html", "sanitizer", "javascript", [79]),
    SecurityFunction("sanitize", "dompurify", "sanitizer", "javascript", [79]),
    SecurityFunction("encodeURIComponent", "global", "sanitizer", "javascript", [79]),
    SecurityFunction("encodeURI", "global", "sanitizer", "javascript", [79]),
    SecurityFunction("parameterize", "pg-format", "sanitizer", "javascript", [89]),
    SecurityFunction("createHmac", "crypto", "sanitizer", "javascript", [327]),
    SecurityFunction("randomBytes", "crypto", "sanitizer", "javascript", [330]),
    # =========================================================================
    # GO — Sinks
    # =========================================================================
    SecurityFunction("Exec", "os/exec.Cmd", "sink", "go", [78]),
    SecurityFunction("Command", "os/exec", "sink", "go", [78]),
    SecurityFunction("Query", "database/sql.DB", "sink", "go", [89]),
    SecurityFunction("QueryRow", "database/sql.DB", "sink", "go", [89]),
    SecurityFunction("Exec", "database/sql.DB", "sink", "go", [89]),
    SecurityFunction("Prepare", "database/sql.DB", "sink", "go", [89]),
    SecurityFunction("Execute", "html/template.Template", "sink", "go", [79]),
    SecurityFunction("Execute", "text/template.Template", "sink", "go", [79]),
    SecurityFunction("Fprintf", "fmt", "sink", "go", [134]),
    SecurityFunction("Sprintf", "fmt", "sink", "go", [134]),
    SecurityFunction("WriteFile", "os", "sink", "go", [22]),
    SecurityFunction("Create", "os", "sink", "go", [22]),
    SecurityFunction("OpenFile", "os", "sink", "go", [22]),
    SecurityFunction("Redirect", "net/http", "sink", "go", [601]),
    SecurityFunction("Get", "net/http", "sink", "go", [918]),
    SecurityFunction("Post", "net/http", "sink", "go", [918]),
    SecurityFunction("Do", "net/http.Client", "sink", "go", [918]),
    SecurityFunction("Unmarshal", "encoding/json", "sink", "go", [502]),
    SecurityFunction("Decode", "encoding/json.Decoder", "sink", "go", [502]),
    SecurityFunction("Unmarshal", "encoding/xml", "sink", "go", [611]),
    # =========================================================================
    # GO — Sources
    # =========================================================================
    SecurityFunction("FormValue", "net/http.Request", "source", "go", [89, 79]),
    SecurityFunction("PostFormValue", "net/http.Request", "source", "go", [89, 79]),
    SecurityFunction("URL.Query", "net/http.Request", "source", "go", [89, 79]),
    SecurityFunction("Header.Get", "net/http.Request", "source", "go", [20]),
    SecurityFunction("Body", "net/http.Request", "source", "go", [89, 79]),
    SecurityFunction("Cookie", "net/http.Request", "source", "go", [20]),
    SecurityFunction("Getenv", "os", "source", "go", [78, 89]),
    SecurityFunction("Args", "os", "source", "go", [78]),
    SecurityFunction("ReadAll", "io", "source", "go", [20]),
    SecurityFunction("Stdin", "os", "source", "go", [20]),
    # =========================================================================
    # GO — Sanitizers
    # =========================================================================
    SecurityFunction("EscapeString", "html", "sanitizer", "go", [79]),
    SecurityFunction("HTMLEscapeString", "html/template", "sanitizer", "go", [79]),
    SecurityFunction("QueryEscape", "net/url", "sanitizer", "go", [89]),
    SecurityFunction("PathEscape", "net/url", "sanitizer", "go", [22]),
    SecurityFunction("QuoteIdentifier", "database/sql", "sanitizer", "go", [89]),
    SecurityFunction("Clean", "path/filepath", "sanitizer", "go", [22]),
    SecurityFunction("Base", "path/filepath", "sanitizer", "go", [22]),
]


def lookup(function_name: str, *, language: str | None = None) -> SecurityFunction | None:
    """Find a security function by name, optionally filtered by language."""
    for entry in SECURITY_DB:
        if entry.name == function_name:
            if language is None or entry.language == language:
                return entry
    return None


def lookup_all(function_name: str, *, language: str | None = None) -> list[SecurityFunction]:
    """Find all matching security functions by name."""
    results = []
    for entry in SECURITY_DB:
        if entry.name == function_name:
            if language is None or entry.language == language:
                results.append(entry)
    return results
