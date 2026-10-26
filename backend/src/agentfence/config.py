from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Which environment we run in (development, test, production).
    env: str = "development"
    # Fail closed is the default. This is invariant I5.
    fail_closed: bool = True
    app_name: str = "AgentFence"

    model_config = SettingsConfigDict(env_prefix="AGENTFENCE_", env_file=".env")


def get_settings() -> Settings:
    return Settings()