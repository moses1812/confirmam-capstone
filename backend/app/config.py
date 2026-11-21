import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that are never accepted as real secrets (they appear in tutorials, old examples and README files).
WEAK_PASSCODES = {"", "admin", "admin123", "password", "passw0rd", "123456", "12345678", "changeme", "change-me", "letmein"}
DEFAULT_SECRETS = {"", "change-this-secret-key", "put-a-long-random-string-here", "change-me", "changeme", "secret"}
DEFAULT_API_KEYS = {"", "change-me", "change-me-long-random-string", "changeme", "testkey"}

_RUNTIME_SECRET = secrets.token_urlsafe(48)  # used only if SECRET_KEY is missing: admin sessions end on every restart


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"  # "production" = refuse to start with weak secrets
    database_url: str = "sqlite:///./confirmam.db"
    # Admin sign-in. NO built-in defaults: run `python -m scripts.make_env` to create them.
    admin_passcode: str = ""
    secret_key: str = ""
    admin_api_key: str = ""  # optional: lets scripts / Swagger call admin endpoints with header X-API-Key
    cors_origins: str = "*"  # comma-separated list of allowed site origins, e.g. https://confirmam.ng
    enable_demo_seed: bool = False  # sample-report endpoint, for demos only
    google_safe_browsing_key: str = ""
    virustotal_key: str = ""
    urlhaus_auth_key: str = ""
    ipqs_key: str = ""
    http_timeout: float = 8.0
    load_feeds_on_start: bool = True
    feed_refresh_hours: int = 24  # 0 = never go online, use the bundled offline snapshot only
    phone_list_enabled: bool = True  # NigeriaPhoneBook reported-number list
    phone_list_refresh_hours: int = 12  # 0 = use the saved file only

    @property
    def admin_login_enabled(self) -> bool:
        return len(self.admin_passcode) >= 10 and self.admin_passcode.lower() not in WEAK_PASSCODES

    @property
    def api_key_enabled(self) -> bool:
        return len(self.admin_api_key) >= 20 and self.admin_api_key.lower() not in DEFAULT_API_KEYS

    @property
    def signing_key(self) -> str:
        ok = len(self.secret_key) >= 32 and self.secret_key.lower() not in DEFAULT_SECRETS
        return self.secret_key if ok else _RUNTIME_SECRET

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()] or ["*"]

    def problems(self) -> list[str]:
        out = []
        if not self.admin_login_enabled:
            out.append("ADMIN_PASSCODE is missing, shorter than 10 characters, or a common default, so admin sign-in is DISABLED.")
        if self.signing_key is _RUNTIME_SECRET:
            out.append("SECRET_KEY is missing, too short (32+ needed) or a default value.")
        if self.admin_api_key and not self.api_key_enabled:
            out.append("ADMIN_API_KEY is too short or a default value, so X-API-Key access is DISABLED.")
        if self.cors_origins.strip() == "*":
            out.append("CORS_ORIGINS is '*' (any website may call the API). Set it to your site's address when you deploy.")
        return out


settings = Settings()
