from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, String, Integer, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy import Index
from sqlalchemy.sql.expression import literal
from datetime import datetime
from flask_login import UserMixin, current_user

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    humanname: Mapped[str] = mapped_column(String(60), nullable=False)
# Нове поле. Треба для друку адреси на ярликах
    dept_id: Mapped[int] = mapped_column(ForeignKey('refill_dept.id'), nullable=False)
    lastlogin: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    active: Mapped[bool] = mapped_column(default=True)
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    role: Mapped[str] = mapped_column(String(30), server_default="user")

class RefillDept(db.Model):
    __tablename__ = "refill_dept"
    id: Mapped[int] = mapped_column(primary_key=True)
    deptname: Mapped[str] = mapped_column(String(30))
    addr1: Mapped[str] = mapped_column(String(255))
    addr2: Mapped[str] = mapped_column(String(255))
    addr3: Mapped[str] = mapped_column(String(255))
    addr4: Mapped[str] = mapped_column(String(255))
    addr5: Mapped[str] = mapped_column(String(255))
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
# Нове поле. Потрібне щоб зразу знати статус картриджа, а не перебирати таблицю історії
    curr_status: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    curr_dept: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

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
        Index('idx_status', 'status'),                                 # Окремий індекс для status
        Index('idx_exec_dept', 'exec_dept'),                           # Окремий індекс для exec_dept
    )

class CartridgeModel(db.Model):
    __tablename__ = 'cartrg_model'
    id = mapped_column(db.Integer, primary_key=True)
    model_name = mapped_column(db.String(128), nullable=False, unique=True)
    model_type = mapped_column(db.Integer, nullable=False)  # 0: Тонер+барабан, 1: Тонер, 2: Барабан, 3: Стрічка, 4: Чорнила
    printer_model_id = mapped_column(db.Integer, db.ForeignKey('model_print.id'), nullable=True)  # Прив’язка до принтера
    user_updated = mapped_column(db.Integer, db.ForeignKey('users.id'))
    time_updated = mapped_column(db.DateTime)


class EventLog(db.Model):
    __tablename__ = "event_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    table_name: Mapped[str] = mapped_column(String(30))
    event_type: Mapped[int] = mapped_column(Integer, server_default=literal(0))
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())