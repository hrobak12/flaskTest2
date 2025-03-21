from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, String, Integer, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy import Index
from sqlalchemy.sql.expression import literal
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    humanname: Mapped[str] = mapped_column(String(60), nullable=False)
    lastlogin: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    active: Mapped[bool] = mapped_column(default=True)
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    role: Mapped[str] = mapped_column(String(30), server_default="user")

class RefillDept(db.Model):
    __tablename__ = "refill_dept"
    id: Mapped[int] = mapped_column(primary_key=True)
    deptname: Mapped[str] = mapped_column(String(30))
    is_exec: Mapped[int] = mapped_column(Integer, server_default=literal(0))
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

class PrinterModel(db.Model):
    __tablename__ = "model_print"
    id: Mapped[int] = mapped_column(primary_key=True)
    model_name: Mapped[str] = mapped_column(String(30))
    ink_type: Mapped[int] = mapped_column(Integer, server_default=literal(0))
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

class CustomerEquipment(db.Model):
    __tablename__ = "custmr_equip"
    id: Mapped[int] = mapped_column(primary_key=True)
    print_model: Mapped[int] = mapped_column(ForeignKey(PrinterModel.id))
    print_dept: Mapped[int] = mapped_column(ForeignKey(RefillDept.id))
    serial_num: Mapped[str] = mapped_column(String(255), server_default="N/A")
    inventory_num: Mapped[str] = mapped_column(String(255), server_default="N/A")
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

class Cartridges(db.Model):
    __tablename__ = "cartridges"
    id: Mapped[int] = mapped_column(primary_key=True)
    serial_num: Mapped[str] = mapped_column(String(255), server_default="N/A")
    in_printer: Mapped[int] = mapped_column(ForeignKey(CustomerEquipment.id), nullable=True)
    cartridge_model: Mapped[str] = mapped_column(String(255), nullable=True)  # Текстове поле
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

class CartridgeStatus(db.Model):
    __tablename__ = "cartrg_status"
    id: Mapped[int] = mapped_column(primary_key=True)
    cartridge_id = mapped_column(ForeignKey(Cartridges.id))
    status: Mapped[int] = mapped_column(Integer, server_default=literal(0))
    date_ofchange: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    parcel_track: Mapped[str] = mapped_column(String(13), nullable=True)
    exec_dept: Mapped[int] = mapped_column(ForeignKey(RefillDept.id))
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    #індекси
    __table_args__ = (
        Index('idx_cartridge_date', 'cartridge_id', 'date_ofchange'),  # Композитний індекс
        Index('idx_status', 'status'),                                # Окремий індекс для status
        Index('idx_exec_dept', 'exec_dept'),                          # Окремий індекс для exec_dept
    )


class EventLog(db.Model):
    __tablename__ = "event_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    table_name: Mapped[str] = mapped_column(String(30))
    event_type: Mapped[int] = mapped_column(Integer, server_default=literal(0))
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())