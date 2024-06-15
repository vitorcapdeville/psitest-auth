import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import BackgroundTasks, Body, Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy_utils import database_exists
from sqlmodel import Session, select

from app.config import Settings
from app.database import criar_db_e_tabelas, engine, get_session
from app.dependencies import get_settings, get_user
from app.models import Token, User

if not database_exists(engine.url):
    criar_db_e_tabelas()


app = FastAPI()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_verification_string():
    return str(uuid4())


def send_email(receiver_email: str, message: str, sender_password: str):
    port = 465
    smtp_server = "smtp.gmail.com"
    sender_email = "vitor771@gmail.com"

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message)


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


@app.post("/login")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.post("/signup")
async def signup(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[Session, Depends(get_session)],
    background_tasks: BackgroundTasks,
):
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

    message = f"""\
Subject: Email confirmation

Thanks for signing up! To verify your email, click here:
{settings.FRONT_END_URL}/verify-email/{verification_string}"""
    background_tasks.add_task(send_email, user.email, message, settings.GOOGLE_APP_PASS)

    return Token(access_token=access_token, token_type="bearer")


@app.put("/verify-email")
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


@app.put("/forgot-password")
async def forgot_password(
    email: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    background_tasks: BackgroundTasks,
):
    print(email)
    user = get_user(session, email)
    if not user:
        return {"detail": "email sent"}

    verification_string = get_verification_string()
    user.reset_password_code = verification_string
    session.add(user)
    session.commit()
    session.refresh(user)

    message = f"""\
Subject: Password reset

To reset your password, click here:
{settings.FRONT_END_URL}/reset-password/{verification_string}"""
    background_tasks.add_task(send_email, user.email, message, settings.GOOGLE_APP_PASS)
    return {"detail": "email sent"}


@app.put("/reset-password")
async def reset_password(
    reset_password_code: str,
    password: Annotated[str, Body()],
    session: Annotated[Session, Depends(get_session)],
):
    statement = select(User).where(User.reset_password_code == reset_password_code)
    user = session.exec(statement).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="verification string not found",
        )
    user.hashed_password = get_password_hash(password)
    user.reset_password_code = None
    session.add(user)
    session.commit()
    session.refresh(user)
