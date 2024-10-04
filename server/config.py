from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Settings(BaseSettings):
    PROJECT_TITLE: str = "TDW Server"
    PROJECT_VERSION: str = "v0"

    SECRET_KEY: str = os.environ["SECRET_KEY"]

    DOMAIN: str = os.environ["DOMAIN"]
    DID_WEB_BASE: str = f"did:web:{DOMAIN}"
    ENDORSER_MULTIKEY: str = os.environ["ENDORSER_MULTIKEY"]

    ASKAR_DB: str = (
        os.environ["POSTGRES_URI"]+'/tdw-server'
        if "POSTGRES_URI" in os.environ
        else "sqlite://app.db"
    )


settings = Settings()
