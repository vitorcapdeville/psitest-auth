from sqlmodel import Field, SQLModel


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: str | None = None


class User(SQLModel, table=True):
    email: str = Field(primary_key=True)
    hashed_password: str
    verified: bool = False
    verification_string: str | None = None
    reset_password_code: str | None = None
