"""Database models and session management for recon data."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


class Program(Base):
    __tablename__ = "programs"

    id = Column(Integer, primary_key=True)
    handle = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    platform = Column(String, nullable=False, default="hackerone")
    submission_state = Column(String, default="open")
    last_synced = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scopes = relationship("Scope", back_populates="program", cascade="all, delete-orphan")
    targets = relationship("Target", back_populates="program", cascade="all, delete-orphan")


class Scope(Base):
    __tablename__ = "scopes"

    id = Column(Integer, primary_key=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False)
    asset_identifier = Column(String, nullable=False)
    asset_type = Column(String, nullable=False)
    eligible_for_bounty = Column(Boolean, default=False)
    eligible_for_submission = Column(Boolean, default=False)
    instruction = Column(Text, default="")

    program = relationship("Program", back_populates="scopes")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False)
    hostname = Column(String, nullable=False, index=True)
    source = Column(String, default="")  # how it was discovered
    ip_address = Column(String, default="")
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    alive = Column(Boolean, default=True)

    program = relationship("Program", back_populates="targets")
    services = relationship("Service", back_populates="target", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    service_name = Column(String, default="")
    version = Column(String, default="")
    banner = Column(Text, default="")
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    target = relationship("Target", back_populates="services")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    vuln_type = Column(String, nullable=False)  # e.g. "subdomain_takeover", "cors_misconfig"
    severity = Column(String, default="medium")  # none, low, medium, high, critical
    confidence = Column(Float, default=0.5)  # 0.0 - 1.0
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    status = Column(String, default="new")  # new, verified, reported, duplicate, false_positive
    reported_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    target = relationship("Target")


def get_engine(db_path: str | Path | None = None):
    if db_path is None:
        db_path = Path(__file__).resolve().parent.parent.parent / "wintermute.db"
    return create_engine(f"sqlite:///{db_path}", echo=False)


def get_session(db_path: str | Path | None = None) -> Session:
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()
