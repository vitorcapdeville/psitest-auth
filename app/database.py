from sqlmodel import Session, SQLModel, create_engine

from app.models import User  # noqa: F401

sqlite_file_name = "database.sqlite"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def criar_db_e_tabelas():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
