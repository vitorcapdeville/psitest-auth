from sqlmodel import Field, SQLModel


class Token(SQLModel):
    access_token: str = Field(description="JWT access token")
    token_type: str = Field(description="Type of token, usually Bearer.")


class User(SQLModel, table=True):
    email: str = Field(primary_key=True)
    hashed_password: str
    verified: bool = False
    verification_string: str | None = None
    reset_password_code: str | None = None


class ValidateResetPasswordCode(SQLModel):
    email: str = Field(description="User e-mail")
    code: str = Field(description="Reset password code")


class ResetPassword(ValidateResetPasswordCode):
    new_password: str = Field(description="New password")
