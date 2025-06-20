from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, String, Integer, DateTime, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column #, DeclarativeBase
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
    dept_description: Mapped[str] = mapped_column(String(255))
    addr1: Mapped[str] = mapped_column(String(255))
    addr2: Mapped[str] = mapped_column(String(255))
    addr3: Mapped[str] = mapped_column(String(255))
    addr4: Mapped[str] = mapped_column(String(255))
    addr5: Mapped[str] = mapped_column(String(255))
    dept_description: Mapped[str] = mapped_column(String(255))  # Нове поле
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

class CartridgeModel(db.Model):
    __tablename__ = 'cartrg_model'
    id = mapped_column(db.Integer, primary_key=True)
    model_name = mapped_column(db.String(128), nullable=False, unique=True)
    model_type = mapped_column(db.Integer, nullable=False)  # 0: Тонер+барабан, 1: Тонер, 2: Барабан, 3: Стрічка, 4: Чорнила
    printer_model_id = mapped_column(db.Integer, db.ForeignKey('model_print.id'), nullable=True)  # Прив’язка до принтера
    user_updated = mapped_column(db.Integer, db.ForeignKey('users.id'))
    time_updated = mapped_column(db.DateTime)

class Cartridges(db.Model):
    __tablename__ = "cartridges"
    id: Mapped[int] = mapped_column(primary_key=True)
    serial_num: Mapped[str] = mapped_column(String(255), server_default="N/A")
    use_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    in_printer: Mapped[int] = mapped_column(ForeignKey(CustomerEquipment.id), nullable=True)
    cartridge_model: Mapped[str] = mapped_column(String(255), nullable=True)  # Застаріле. Не використовувати!
    cartrg_model_id: Mapped[int] = mapped_column(ForeignKey(CartridgeModel.id), default=1)
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
# Нове поле. Потрібне щоб зразу знати поточний статус картриджа, а не перебирати таблицю історії
    curr_status: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    curr_dept: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    curr_parcel_track: Mapped[str] = mapped_column(String(13), nullable=True)

class CartridgeStatus(db.Model):
    __tablename__ = "cartrg_status"
    id: Mapped[int] = mapped_column(primary_key=True)
    cartridge_id = mapped_column(ForeignKey(Cartridges.id))
    device_id: Mapped[int] = mapped_column(ForeignKey(CustomerEquipment.id), nullable=True)
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

class CompatibleCartridges(db.Model):
    __tablename__ = "compat_cartridges"
    id: Mapped[int] = mapped_column(primary_key=True)
    printer_model_id: Mapped[int] = mapped_column(ForeignKey('model_print.id'), nullable=False)
    cartridge_model_id: Mapped[int] = mapped_column(ForeignKey('cartrg_model.id'), nullable=False)
    notes: Mapped[str] = mapped_column(String(255), nullable=True)
    user_updated: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    __table_args__ = (
        Index('idx_printer_model', 'printer_model_id'),
        Index('idx_cartridge_model', 'cartridge_model_id'),
        db.UniqueConstraint('printer_model_id', 'cartridge_model_id', name='uniq_printer_cartridge'),
    )

class Contracts(db.Model):
    __tablename__ = "contracts"
    id: Mapped[int] = mapped_column(primary_key=True)
    contract_number: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    signing_date: Mapped[datetime.date] = mapped_column(DateTime, nullable=False)
    expiry_date: Mapped[datetime.date] = mapped_column(DateTime, nullable=True)
    contractor_id: Mapped[int] = mapped_column(ForeignKey('refill_dept.id'), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default='active')
    user_updated: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    time_updated: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    __table_args__ = (
        Index('idx_contract_contractor', 'contractor_id'),
    )

class ContractsServicesBalance(db.Model):
    __tablename__ = "contract_services_balance"
    id: Mapped[int] = mapped_column(primary_key=True)
    RefillServiceName: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    contract_id: Mapped[int] = mapped_column(ForeignKey('contracts.id'), nullable=False)
    service_type: Mapped[int] = mapped_column(Integer, nullable=False)
    balance: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    initial_balance: Mapped[int] = mapped_column(Integer, nullable=False, default=0) #26.05.25
    user_updated: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    __table_args__ = (
        UniqueConstraint('contract_id', 'service_type', 'RefillServiceName', name='uniq_service_balance'),
        Index('idx_contract_service', 'contract_id'),
        Index('idx_service_name', 'RefillServiceName'),
    )

class CompatibleServices(db.Model):
    __tablename__ = "compatible_services"
    id: Mapped[int] = mapped_column(primary_key=True)
    cartridge_model_id: Mapped[int] = mapped_column(ForeignKey('cartrg_model.id'), nullable=False)
    service_id: Mapped[int] = mapped_column(ForeignKey('contract_services_balance.id'), nullable=False)
    user_updated: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    __table_args__ = (
        UniqueConstraint('cartridge_model_id', 'service_id', name='uniq_cartridge_service'),
        Index('idx_compat_cartridge_model', 'cartridge_model_id'),
        Index('idx_compat_service_id', 'service_id'),
    )



class EventLog(db.Model):
    __tablename__ = "event_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    table_name: Mapped[str] = mapped_column(String(30))
    event_type: Mapped[int] = mapped_column(Integer, server_default=literal(0))
    user_updated: Mapped[int] = mapped_column(ForeignKey(User.id))
    time_updated: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())