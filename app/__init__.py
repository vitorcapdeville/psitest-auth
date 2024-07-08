import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import quote_plus

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy_utils import database_exists
from sqlmodel import Session, select

from app.config import Settings
from app.database import criar_db_e_tabelas, engine, get_session
from app.dependencies import get_current_user, get_settings, get_user
from app.models import ResetPassword, Token, User, ValidateResetPasswordCode

if not database_exists(engine.url):
    criar_db_e_tabelas()


app = FastAPI()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_verification_string():
    digitos = "0123456789"
    codigo = "".join(secrets.choice(digitos) for _ in range(6))
    return codigo


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(session: Session, username: str, password: str):
    user = get_user(session, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, settings: Settings, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


@app.post("/login", description="Login with e-mail and password.")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "verified": user.verified},
        settings=settings,
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/signup", description="Sign up with e-mail and password.")
async def signup(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[Session, Depends(get_session)],
) -> Token:
    if get_user(session, form_data.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail já cadastrado.",
        )

    verification_string = get_verification_string()
    hashed_password = get_password_hash(form_data.password)
    user = User(
        email=form_data.username,
        hashed_password=hashed_password,
        verified=False,
        verification_string=verification_string,
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "verified": user.verified},
        settings=settings,
        expires_delta=access_token_expires,
    )

    data = {
        "email": quote_plus(user.email),
        "subject": "Email confirmation",
        "message": f"Use this code to confirm your email in PsiTest: {verification_string}",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{settings.PSITEST_EMAILS}/send-email", json=data)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return Token(access_token=access_token, token_type="bearer")


@app.put("/verify-email", description="Verify e-mail with verification string.")
async def verify_email(
    verification_string: Annotated[str, Body()],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    stmt = select(User).where(User.verification_string == verification_string)
    user = session.exec(stmt).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="verification string not found",
        )
    user.verified = True
    user.verification_string = None
    session.add(user)
    session.commit()
    session.refresh(user)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "verified": user.verified},
        settings=settings,
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.put("/forgot-password", description="Send e-mail with reset password code.")
async def forgot_password(
    email: Annotated[str, Body()],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    user = get_user(session, email)
    if not user:
        return {"detail": "email sent"}

    verification_string = get_verification_string()
    user.reset_password_code = verification_string
    session.add(user)
    session.commit()
    session.refresh(user)

    data = {
        "email": quote_plus(user.email),
        "subject": "Password reset",
        "message": f"To reset your password in PsiTest, use this code: {verification_string}",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{settings.PSITEST_EMAILS}/send-email", json=data)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)


@app.post("/validate-reset-password-code", description="Validate reset password code.")
async def validate_reset_password_code(
    validate_data: ValidateResetPasswordCode,
    session: Annotated[Session, Depends(get_session)],
) -> None:
    statement = select(User).where(User.email == validate_data.email)
    user = session.exec(statement).one_or_none()
    if not user or user.reset_password_code != validate_data.code:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="user not found or reset code incorrect",
        )


@app.put("/reset-password", description="Reset password with reset password code and new password.")
async def reset_password(
    reset_password: ResetPassword,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    statement = select(User).where(User.email == reset_password.email)
    user = session.exec(statement).one_or_none()
    if not user or user.reset_password_code != reset_password.code:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="user not found or reset code incorrect",
        )
    user.hashed_password = get_password_hash(reset_password.new_password)
    user.reset_password_code = None
    session.add(user)
    session.commit()
    session.refresh(user)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "verified": user.verified},
        settings=settings,
        expires_delta=access_token_expires,
    )

    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me", description="Get current user e-mail based on JWT.")
async def get_current_user_email(
    current_user: Annotated[User, Depends(get_current_user)],
) -> str:
    return current_user
