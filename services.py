from sqlalchemy import asc, desc
from sqlalchemy.exc import IntegrityError
from models import *
from config import status_map
from datetime import datetime
import bcrypt

#-----------------------------------------------------------------------------------------------------------------------
def getDepartmentsList(is_exec=None, order='asc'):
    """
    Отримує список відділів як список словників із фільтрацією за is_exec і сортуванням за deptname.

    Args:
        is_exec (int, optional): Значення is_exec (0, 1 або 2) для фільтрації.
        order (str): Порядок сортування ('asc' або 'desc').

    Returns:
        list: Список словників із полями deptname, dept_description, addr1-addr5.
    """
    query = RefillDept.query

    # Фільтрація за is_exec (якщо надано)
    if is_exec is not None:
        query = query.filter(RefillDept.is_exec == is_exec)

    # Сортування за deptname
    if order.lower() == 'desc':
        query = query.order_by(desc(RefillDept.deptname))
    else:
        query = query.order_by(asc(RefillDept.deptname))

    # Формування списку словників із потрібними полями
    data = [
        {
            'id': dept.id,
            'deptname': dept.deptname,
            'dept_description': dept.dept_description or '',
            'addr1': dept.addr1 or '',
            'addr2': dept.addr2 or '',
            'addr3': dept.addr3 or '',
            'addr4': dept.addr4 or '',
            'addr5': dept.addr5 or '',
            'is_exec': dept.is_exec
        }
        for dept in query.all()
    ]

    return data
#-----------------------------------------------------------------------------------------------------------------------
def getCartridgesList(status_list=None, status_sort='asc'):
    """
    Отримує список картриджів як список словників із фільтрацією за списком статусів і сортуванням.

    Args:
        status_list (list, optional): Список статусів для фільтрації (наприклад, [1, 5, 6]). Якщо None, повертаються всі
            картриджі.
        status_sort (str): Порядок сортування ('asc' або 'desc').

    Returns:
        list: Список словників із полями id, serial_num, cartridge_model, status, date_ofchange, dept_name,
            parcel_track
    """
    # Визначення функції сортування
    sort_func = asc if status_sort.lower() == 'asc' else desc

    # Запит до Cartridges із приєднанням RefillDept та CartridgeModel
    query = db.session.query(Cartridges, RefillDept.deptname, CartridgeModel.model_name)\
                     .outerjoin(RefillDept, Cartridges.curr_dept == RefillDept.id)\
                     .outerjoin(CartridgeModel, Cartridges.cartrg_model_id == CartridgeModel.id)

    # Фільтрація за status_list, якщо надано
    if status_list is not None:
        query = query.filter(Cartridges.curr_status.in_(status_list))

    # Сортування за time_updated
    query = query.order_by(sort_func(Cartridges.time_updated))

    # Формування списку словників
    data = [
        {
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': model_name or 'Не вказано',
            'status': cartridge.curr_status,
            'date_ofchange': cartridge.time_updated.strftime('%Y-%m-%d') if cartridge.time_updated else None,
            'dept_name': dept_name or 'Не вказано',
            'parcel_track': cartridge.curr_parcel_track or ''
        }
        for cartridge, dept_name, model_name in query.all()
    ]

    return data
#-----------------------------------------------------------------------------------------------------------------------
def getStatusList():
    """
    Отримує список статусів як список словників

    Args:
        Відсутні.

    Returns:
        list: Список словників із полями status_id, status_name.
    """
    data = [
        {"status_id": status_id, "status_name": status_name}
        for status_id, status_name in status_map.items()
    ]

    return data
#-----------------------------------------------------------------------------------------------------------------------
def getCartridgeData(serial: str) -> dict | None:
    """
    Отримує дані картриджа за серійним номером.

    Args:
        serial (str): Серійний номер картриджа.

    Returns:
        dict | None: Словник із даними картриджа або None, якщо не знайдено.
    """
    cartridge = db.session.query(Cartridges).filter_by(serial_num=serial).first()
    if not cartridge:
        return None

    data = {
        field: getattr(cartridge, field) if field != "time_updated"
        else cartridge.time_updated.isoformat() if cartridge.time_updated else None
        for field in [
            "id", "serial_num", "in_printer", "cartridge_model", "cartrg_model_id",
            "user_updated", "time_updated", "curr_status", "curr_dept", "curr_parcel_track", "use_counter"
        ]
    }

    return data
#-----------------------------------------------------------------------------------------------------------------------
def createCartridgeData(data, user_id):
    """
    Створює новий картридж у базі даних.

    Args:
        data (dict): Словник із полями serial_num, cartrg_model_id, in_printer, use_counter.
        user_id (int): ID користувача, який створює картридж.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        # Валідація обов’язкових полів
        serial_num = data.get("serial_num")
        if not serial_num:
            return {"success": False, "message": "Серійний номер обов’язковий"}

        # Перевірка унікальності serial_num
        if Cartridges.query.filter_by(serial_num=serial_num).first():
            return {"success": False, "message": "Картридж із таким серійним номером уже існує"}

        # Валідація cartrg_model_id
        cartrg_model_id = data.get("cartrg_model_id")
        if cartrg_model_id and not CartridgeModel.query.get(cartrg_model_id):
            return {"success": False, "message": "Недійсна модель картриджа"}

        # Валідація in_printer
        in_printer = data.get("in_printer")
        if in_printer and not CustomerEquipment.query.get(in_printer):
            return {"success": False, "message": "Недійсний принтер"}

        # Валідація user_id
        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        # Створення картриджа
        cartridge = Cartridges(
            serial_num=serial_num,
            cartrg_model_id=cartrg_model_id if cartrg_model_id else None,
            in_printer=in_printer if in_printer else None,
            use_counter=int(data.get("use_counter", -1)),
            curr_status=0,  # За замовчуванням "Не вказано"
            user_updated=user_id,
            time_updated=datetime.utcnow()
        )

        db.session.add(cartridge)
        db.session.commit()
        return {"success": True, "message": "Картридж створено успішно"}

    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення унікальності даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def removeCartridgeData(serial: str) -> dict:
    """
    Видаляє картридж за серійним номером.

    Args:
        serial (str): Серійний номер картриджа.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        cartridge = Cartridges.query.filter_by(serial_num=serial).first()
        if not cartridge:
            return {"success": False, "message": "Картридж не знайдено"}

        db.session.delete(cartridge)
        db.session.commit()
        return {"success": True, "message": "Картридж видалено успішно"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def modifyCartridgeData(data: dict, user_id: int) -> dict:
    """
    Оновлює дані картриджа в базі даних.

    Args:
        data (dict): Словник із полями cartridge_id, serial_num, cartrg_model_id, in_printer, use_counter.
        user_id (int): ID користувача, який оновлює картридж.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        # Валідація обов’язкових полів
        cartridge_id = data.get("cartridge_id")
        serial_num = data.get("serial_num")
        if not cartridge_id or not serial_num:
            return {"success": False, "message": "ID картриджа та серійний номер обов’язкові"}

        # Перевірка існування картриджа
        cartridge = Cartridges.query.get(cartridge_id)
        if not cartridge:
            return {"success": False, "message": "Картридж не знайдено"}

        # Перевірка унікальності serial_num (якщо змінюється)
        if serial_num != cartridge.serial_num:
            if Cartridges.query.filter_by(serial_num=serial_num).first():
                return {"success": False, "message": "Картридж із таким серійним номером уже існує"}

        # Валідація cartrg_model_id
        cartrg_model_id = data.get("cartrg_model_id")
        if cartrg_model_id and not CartridgeModel.query.get(cartrg_model_id):
            return {"success": False, "message": "Недійсна модель картриджа"}

        # Валідація in_printer
        in_printer = data.get("in_printer")
        if in_printer and not CustomerEquipment.query.get(in_printer):
            return {"success": False, "message": "Недійсний принтер"}

        # Валідація user_id
        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        # Оновлення полів
        cartridge.serial_num = serial_num
        cartridge.cartrg_model_id = cartrg_model_id if cartrg_model_id else None
        cartridge.in_printer = in_printer if in_printer else None
        cartridge.use_counter = int(data.get("use_counter", -1))
        cartridge.user_updated = user_id
        cartridge.time_updated = datetime.utcnow()

        db.session.commit()
        return {"success": True, "message": "Картридж оновлено успішно"}

    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення унікальності даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def getPrinterData(identifier: str) -> dict:
    """
    Отримує дані принтера за інвентарним номером.

    Args:
        identifier (str): Інвентарний номер принтера.

    Returns:
        dict: Дані принтера або помилка {"success": bool, "message": str, "data": dict}.
    """
    try:
        printer = CustomerEquipment.query.filter_by(inventory_num=identifier).first()
        if not printer:
            return {"success": False, "message": "Принтер не знайдено", "data": {}}

        return {
            "success": True,
            "message": "Дані отримано",
            "data": {
                "id": printer.id,
                "serial_num": printer.serial_num,
                "inventory_num": printer.inventory_num,
                "print_model": printer.print_model,
                "print_dept": printer.print_dept
            }
        }
    except Exception as e:
        return {"success": False, "message": f"Помилка: {str(e)}", "data": {}}
# -----------------------------------------------------------------------------------------------------------------------
def createPrinterData(data: dict, user_id: int) -> dict:
    """
    Створює новий принтер у базі даних.

    Args:
        data (dict): Словник із полями serial_num, inventory_num, print_model, print_dept.
        user_id (int): ID користувача, який додає принтер.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        inventory_num = data.get("inventory_num")
        if not inventory_num:
            return {"success": False, "message": "Інвентарний номер обов’язковий"}

        if CustomerEquipment.query.filter_by(inventory_num=inventory_num).first():
            return {"success": False, "message": "Принтер із таким інвентарним номером уже існує"}

        print_model = data.get("print_model")
        if print_model and not PrinterModel.query.get(print_model):
            return {"success": False, "message": "Недійсна модель принтера"}

        print_dept = data.get("print_dept")
        if print_dept and not RefillDept.query.get(print_dept):
            return {"success": False, "message": "Недійсний відділ"}

        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        printer = CustomerEquipment(
            serial_num=data.get("serial_num", "N/A"),
            inventory_num=inventory_num,
            print_model=print_model if print_model else None,
            print_dept=print_dept if print_dept else None,
            user_updated=user_id,
            time_updated=datetime.utcnow()
        )

        db.session.add(printer)
        db.session.commit()
        return {"success": True, "message": "Принтер додано успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення унікальності даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def removePrinterData(identifier: str) -> dict:
    """
    Видаляє принтер за інвентарним номером.

    Args:
        identifier (str): Інвентарний номер принтера.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        printer = CustomerEquipment.query.filter_by(inventory_num=identifier).first()
        if not printer:
            return {"success": False, "message": "Принтер не знайдено"}

        db.session.delete(printer)
        db.session.commit()
        return {"success": True, "message": "Принтер видалено успішно"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def modifyPrinterData(data: dict, user_id: int) -> dict:
    """
    Оновлює дані принтера в базі даних.

    Args:
        data (dict): Словник із полями printer_id, serial_num, inventory_num, print_model, print_dept.
        user_id (int): ID користувача, який оновлює принтер.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        printer_id = data.get("printer_id")
        inventory_num = data.get("inventory_num")
        if not printer_id or not inventory_num:
            return {"success": False, "message": "ID принтера та інвентарний номер обов’язкові"}

        printer = CustomerEquipment.query.get(printer_id)
        if not printer:
            return {"success": False, "message": "Принтер не знайдено"}

        if inventory_num != printer.inventory_num:
            if CustomerEquipment.query.filter_by(inventory_num=inventory_num).first():
                return {"success": False, "message": "Принтер із таким інвентарним номером уже існує"}

        print_model = data.get("print_model")
        if print_model and not PrinterModel.query.get(print_model):
            return {"success": False, "message": "Недійсна модель принтера"}

        print_dept = data.get("print_dept")
        if print_dept and not RefillDept.query.get(print_dept):
            return {"success": False, "message": "Недійсний відділ"}

        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        printer.serial_num = data.get("serial_num", "N/A")
        printer.inventory_num = inventory_num
        printer.print_model = print_model if print_model else None
        printer.print_dept = print_dept if print_dept else None
        printer.user_updated = user_id
        printer.time_updated = datetime.utcnow()

        db.session.commit()
        return {"success": True, "message": "Принтер оновлено успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення унікальності даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def GetDeptData(dept_id: int) -> dict:
    """
    Отримує дані відділу за ID.

    Args:
        dept_id (int): ID відділу.

    Returns:
        dict: Дані відділу або помилка {"success": bool, "message": str, "data": dict}.
    """
    try:
        dept = RefillDept.query.get(dept_id)
        if not dept:
            return {"success": False, "message": "Відділ не знайдено", "data": {}}

        return {
            "success": True,
            "message": "Дані отримано",
            "data": {
                "id": dept.id,
                "deptname": dept.deptname,
                "dept_description": dept.dept_description,
                "addr1": dept.addr1,
                "addr2": dept.addr2,
                "addr3": dept.addr3,
                "addr4": dept.addr4,
                "addr5": dept.addr5,
                "is_exec": dept.is_exec
            }
        }
    except Exception as e:
        return {"success": False, "message": f"Помилка: {str(e)}", "data": {}}
# -----------------------------------------------------------------------------------------------------------------------
def CreateDept(data: dict, user_id: int) -> dict:
    """
    Створює новий відділ у базі даних.

    Args:
        data (dict): Словник із полями deptname, dept_description, addr1-addr5, is_exec.
        user_id (int): ID користувача, який додає відділ.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        deptname = data.get("deptname")
        if not deptname:
            return {"success": False, "message": "Назва відділу обов’язкова"}

        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        is_exec = int(data.get("is_exec", 0))
        if is_exec not in [0, 1, 2]:
            return {"success": False, "message": "Недійсний тип відділу"}

        dept = RefillDept(
            deptname=deptname,
            dept_description=data.get("dept_description", ""),
            addr1=data.get("addr1", ""),
            addr2=data.get("addr2", ""),
            addr3=data.get("addr3", ""),
            addr4=data.get("addr4", ""),
            addr5=data.get("addr5", ""),
            is_exec=is_exec,
            user_updated=user_id,
            time_updated=datetime.utcnow()
        )

        db.session.add(dept)
        db.session.commit()
        return {"success": True, "message": "Відділ додано успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def DeleteDept(dept_id: int, user_id: int) -> dict:
    """
    Видаляє відділ за ID із логуванням.

    Args:
        dept_id (int): ID відділу.
        user_id (int): ID користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        dept = RefillDept.query.get(dept_id)
        if not dept:
            return {"success": False, "message": "Відділ не знайдено"}

        # Перевірка використання
        if CustomerEquipment.query.filter_by(print_dept=dept_id).first() or \
           CartridgeStatus.query.filter_by(exec_dept=dept_id).first():
            return {"success": False, "message": "Відділ використовується в обладнанні або статусах"}

        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        db.session.delete(dept)
        event = EventLog(
            table_name='refill_dept',
            event_type=3,
            user_updated=current_user.id
        )
        db.session.add(event)
        db.session.commit()
        return {"success": True, "message": "Відділ видалено успішно"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def ModifyDept(data: dict, user_id: int) -> dict:
    """
    Оновлює дані відділу в базі даних.

    Args:
        data (dict): Словник із полями dept_id, deptname, dept_description, addr1-addr5, is_exec.
        user_id (int): ID користувача, який оновлює відділ.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        dept_id = data.get("dept_id")
        deptname = data.get("deptname")
        if not dept_id or not deptname:
            return {"success": False, "message": "ID відділу та назва необхідні"}

        dept = RefillDept.query.get(dept_id)
        if not dept:
            return {"success": False, "message": "Відділ не знайдено"}

        if not user_id or not User.query.get(user_id):
            return {"success": False, "message": "Недійсний користувач"}

        is_exec = int(data.get("is_exec", 0))
        if is_exec not in [0, 1, 2]:
            return {"success": False, "message": "Недійсний тип відділу"}

        dept.deptname = deptname
        dept.dept_description = data.get("dept_description", "")
        dept.addr1 = data.get("addr1", "")
        dept.addr2 = data.get("addr2", "")
        dept.addr3 = data.get("addr3", "")
        dept.addr4 = data.get("addr4", "")
        dept.addr5 = data.get("addr5", "")
        dept.is_exec = is_exec
        dept.user_updated = user_id
        dept.time_updated = datetime.utcnow()

        db.session.commit()
        return {"success": True, "message": "Відділ оновлено успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def GetUserData(user_id: int) -> dict:
    """
    Отримує дані користувача за ID.

    Args:
        user_id (int): ID користувача.

    Returns:
        dict: Дані користувача або помилка {"success": bool, "message": str, "data": dict}.
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return {"success": False, "message": "Користувач не знайдено", "data": {}}

        return {
            "success": True,
            "message": "Дані отримано",
            "data": {
                "id": user.id,
                "username": user.username,
                "humanname": user.humanname,
                "dept_id": user.dept_id,
                "role": user.role,
                "active": user.active
            }
        }
    except Exception as e:
        return {"success": False, "message": f"Помилка: {str(e)}", "data": {}}
# -----------------------------------------------------------------------------------------------------------------------
def CreateUser(data: dict, current_user_id: int) -> dict:
    """
    Створює нового користувача у базі даних.

    Args:
        data (dict): Словник із полями username, password, humanname, dept_id, role, active.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        username = data.get("username")
        password = data.get("password")
        humanname = data.get("humanname")
        dept_id = data.get("dept_id")
        role = data.get("role")
        active = data.get("active", False)

        if not username or not password or not humanname or not dept_id or not role:
            return {"success": False, "message": "Усі поля, крім пароля, обов’язкові"}

        if User.query.filter_by(username=username).first():
            return {"success": False, "message": "Користувач із таким логіном уже існує"}

        if not RefillDept.query.get(dept_id):
            return {"success": False, "message": "Недійсний відділ"}

        if role not in ['user', 'admin']:
            return {"success": False, "message": "Недійсна роль"}

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(
            username=username,
            password=hashed_password,
            humanname=humanname,
            dept_id=int(dept_id),
            role=role,
            active=active,
            time_updated=datetime.utcnow()
        )

        db.session.add(new_user)
        db.session.commit()
        return {"success": True, "message": "Користувача додано успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def DeleteUser(user_id: int, current_user_id: int) -> dict:
    """
    Видаляє користувача за ID із логуванням.

    Args:
        user_id (int): ID користувача.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return {"success": False, "message": "Користувач не знайдено"}

        if user.id == current_user_id:
            return {"success": False, "message": "Ви не можете видалити себе"}

        db.session.delete(user)
        event = EventLog(
            table_name='users',
            event_type=3,
            user_updated=current_user_id
        )
        db.session.add(event)
        db.session.commit()
        return {"success": True, "message": "Користувача видалено успішно"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def EditUser(data: dict, current_user_id: int) -> dict:
    """
    Оновлює дані користувача у базі даних.

    Args:
        data (dict): Словник із полями user_id, username, password, humanname, dept_id, role, active.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        user_id = data.get("user_id")
        username = data.get("username")
        password = data.get("password")
        humanname = data.get("humanname")
        dept_id = data.get("dept_id")
        role = data.get("role")
        active = data.get("active", False)

        if not user_id or not username or not humanname or not dept_id or not role:
            return {"success": False, "message": "Необхідні поля не заповнено"}

        user = User.query.get(user_id)
        if not user:
            return {"success": False, "message": "Користувач не знайдено"}

        if User.query.filter(User.username == username, User.id != user_id).first():
            return {"success": False, "message": "Користувач із таким логіном уже існує"}

        if not RefillDept.query.get(int(dept_id)):
            return {"success": False, "message": "Недійсний відділ"}

        if role not in ['user', 'admin']:
            return {"success": False, "message": "Недійсна роль"}

        user.username = username
        if password:
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.humanname = humanname
        user.dept_id = int(dept_id)
        user.role = role
        user.active = active
        user.time_updated = datetime.utcnow()

        db.session.commit()
        return {"success": True, "message": "Користувача оновлено успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def GetPrinterModelData(model_id: int) -> dict:
    """
    Отримує дані моделі принтера за ID.

    Args:
        model_id (int): ID моделі.

    Returns:
        dict: Дані моделі або помилка {"success": bool, "message": str, "data": dict}.
    """
    try:
        model = PrinterModel.query.get(model_id)
        if not model:
            return {"success": False, "message": "Модель не знайдено", "data": {}}

        return {
            "success": True,
            "message": "Дані отримано",
            "data": {
                "id": model.id,
                "model_name": model.model_name,
                "ink_type": model.ink_type
            }
        }
    except Exception as e:
        return {"success": False, "message": f"Помилка: {str(e)}", "data": {}}
# -----------------------------------------------------------------------------------------------------------------------
def CreatePrinterModel(data: dict, current_user_id: int) -> dict:
    """
    Створює нову модель принтера у базі даних.

    Args:
        data (dict): Словник із полями model_name, ink_type.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        model_name = data.get("model_name")
        ink_type = data.get("ink_type")

        if not model_name or ink_type is None:
            return {"success": False, "message": "Усі поля обов’язкові"}

        if PrinterModel.query.filter_by(model_name=model_name).first():
            return {"success": False, "message": "Модель із такою назвою уже існує"}

        ink_type = int(ink_type)
        if ink_type not in [0, 1, 2]:
            return {"success": False, "message": "Недопустимий тип чорнил"}

        new_model = PrinterModel(
            model_name=model_name,
            ink_type=ink_type,
            user_updated=current_user_id
        )

        db.session.add(new_model)
        db.session.commit()
        return {"success": True, "message": "Модель додано успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def DeletePrinterModel(model_id: int, current_user_id: int) -> dict:
    """
    Видаляє модель принтера за ID із логуванням.

    Args:
        model_id (int): ID моделі.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        model = PrinterModel.query.get(model_id)
        if not model:
            return {"success": False, "message": "Модель не знайдено"}

        db.session.delete(model)
        event = EventLog(
            table_name='model_print',
            event_type=3,
            user_updated=current_user_id
        )
        db.session.add(event)
        db.session.commit()
        return {"success": True, "message": "Модель видалено успішно"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def EditPrinterModel(data: dict, current_user_id: int) -> dict:
    """
    Оновлює дані моделі принтера у базі даних.

    Args:
        data (dict): Словник із полями model_id, model_name, ink_type.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        model_id = data.get("model_id")
        model_name = data.get("model_name")
        ink_type = data.get("ink_type")

        if not model_id or not model_name or ink_type is None:
            return {"success": False, "message": "Усі поля необхідні"}

        model = PrinterModel.query.get(model_id)
        if not model:
            return {"success": False, "message": "Модель не знайдено"}

        if PrinterModel.query.filter(PrinterModel.model_name == model_name, PrinterModel.id != model_id).first():
            return {"success": False, "message": "Модель із такою назвою уже існує"}

        ink_type = int(ink_type)
        if ink_type not in [0, 1, 2]:
            return {"success": False, "message": "Недопустимий тип чорнил"}

        model.model_name = model_name
        model.ink_type = ink_type
        model.user_updated = current_user_id

        db.session.commit()
        return {"success": True, "message": "Модель оновлено успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def GetCartridgeModelData(model_id: int) -> dict:
    """
    Отримує дані моделі картриджа за ID.

    Args:
        model_id (int): ID моделі.

    Returns:
        dict: Дані моделі або помилка {"success": bool, "message": str, "data": dict}.
    """
    try:
        model = CartridgeModel.query.get(model_id)
        if not model:
            return {"success": False, "message": "Модель не знайдено", "data": {}}

        return {
            "success": True,
            "message": "Дані отримано",
            "data": {
                "id": model.id,
                "model_name": model.model_name,
                "model_type": model.model_type,
                "printer_model_id": model.printer_model_id
            }
        }
    except Exception as e:
        return {"success": False, "message": f"Помилка: {str(e)}", "data": {}}
# -----------------------------------------------------------------------------------------------------------------------
def CreateCartridgeModel(data: dict, current_user_id: int) -> dict:
    """
    Створює нову модель картриджа у базі даних.

    Args:
        data (dict): Словник із полями model_name, model_type, printer_model_id (опціонально).
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        model_name = data.get("model_name")
        model_type = data.get("model_type")
        printer_model_id = data.get("printer_model_id")

        if not model_name or model_type is None:
            return {"success": False, "message": "Усі обов’язкові поля необхідно заповнити"}

        if CartridgeModel.query.filter_by(model_name=model_name).first():
            return {"success": False, "message": "Модель із такою назвою уже існує"}

        model_type = int(model_type)
        if model_type not in [0, 1, 2, 3, 4]:
            return {"success": False, "message": "Недопустимий тип картриджа"}

        if printer_model_id:
            printer_model_id = int(printer_model_id)
            if not PrinterModel.query.get(printer_model_id):
                return {"success": False, "message": "Модель принтера не знайдено"}
        else:
            printer_model_id = None

        new_model = CartridgeModel(
            model_name=model_name,
            model_type=model_type,
            printer_model_id=printer_model_id,
            user_updated=current_user_id,
            time_updated=datetime.utcnow()
        )

        db.session.add(new_model)
        db.session.commit()
        return {"success": True, "message": "Модель додано успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
def DeleteCartridgeModel(model_id: int, current_user_id: int) -> dict:
    """
    Видаляє модель картриджа за ID із логуванням.

    Args:
        model_id (int): ID моделі.
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        model = CartridgeModel.query.get(model_id)
        if not model:
            return {"success": False, "message": "Модель не знайдено"}

        db.session.delete(model)
        event = EventLog(
            table_name='cartrg_model',
            event_type=3,
            user_updated=current_user_id
        )
        db.session.add(event)
        db.session.commit()
        return {"success": True, "message": "Модель видалено успішно"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}

def EditCartridgeModel(data: dict, current_user_id: int) -> dict:
    """
    Оновлює дані моделі картриджа у базі даних.

    Args:
        data (dict): Словник із полями model_id, model_name, model_type, printer_model_id (опціонально).
        current_user_id (int): ID поточного користувача.

    Returns:
        dict: Результат {"success": bool, "message": str}.
    """
    try:
        model_id = data.get("model_id")
        model_name = data.get("model_name")
        model_type = data.get("model_type")
        printer_model_id = data.get("printer_model_id")

        if not model_id or not model_name or model_type is None:
            return {"success": False, "message": "Усі обов’язкові поля необхідно заповнити"}

        model = CartridgeModel.query.get(model_id)
        if not model:
            return {"success": False, "message": "Модель не знайдено"}

        if CartridgeModel.query.filter(CartridgeModel.model_name == model_name, CartridgeModel.id != model_id).first():
            return {"success": False, "message": "Модель із такою назвою уже існує"}

        model_type = int(model_type)
        if model_type not in [0, 1, 2, 3, 4]:
            return {"success": False, "message": "Недопустимий тип картриджа"}

        if printer_model_id:
            printer_model_id = int(printer_model_id)
            if not PrinterModel.query.get(printer_model_id):
                return {"success": False, "message": "Модель принтера не знайдено"}
        else:
            printer_model_id = None

        model.model_name = model_name
        model.model_type = model_type
        model.printer_model_id = printer_model_id
        model.user_updated = current_user_id
        model.time_updated = datetime.utcnow()

        db.session.commit()
        return {"success": True, "message": "Модель оновлено успішно"}
    except IntegrityError:
        db.session.rollback()
        return {"success": False, "message": "Помилка: порушення даних"}
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": f"Помилка: {str(e)}"}
# -----------------------------------------------------------------------------------------------------------------------
from sqlalchemy import or_
from models import CartridgeStatus, Cartridges, RefillDept

def GetDeptCartridgeHistory(dept_id: int = None, dept_name: str = None) -> dict:
    """
    Отримує історію видачі картриджів для підрозділу за ID або назвою.

    Args:
        dept_id (int, optional): ID підрозділу.
        dept_name (str, optional): Назва підрозділу.

    Returns:
        dict: Результат {"success": bool, "message": str, "data": list}.
              data - список словників із serial_num, model_name, date_ofchange, parcel_track.
    """
    try:
        if not dept_id and not dept_name:
            return {
                "success": False,
                "message": "Потрібно вказати ID або назву підрозділу",
                "data": []
            }

        # Шукаємо підрозділ
        dept = None
        if dept_id:
            dept = RefillDept.query.get(dept_id)
        elif dept_name:
            dept = RefillDept.query.filter_by(deptname=dept_name).first()

        if not dept:
            return {
                "success": False,
                "message": "Підрозділ не знайдено",
                "data": []
            }

        # Отримуємо історію з явним вибором моделей
        history = (
            db.session.query(CartridgeStatus, Cartridges, CartridgeModel)
            .join(Cartridges, CartridgeStatus.cartridge_id == Cartridges.id)
            .join(CartridgeModel, Cartridges.cartrg_model_id == CartridgeModel.id)
            .filter(
                CartridgeStatus.exec_dept == dept.id,
                CartridgeStatus.status.in_([2, 5])
            )
            .order_by(CartridgeStatus.date_ofchange.desc())
            .all()
        )

        # Формуємо результат
        result = [
            {
                'serial_num': cartridge.serial_num,
                'model_name': model.model_name,
                'date_ofchange': status.date_ofchange.isoformat() if status.date_ofchange else None,
                'parcel_track': status.parcel_track
            }
            for status, cartridge, model in history
        ]

        return {
            "success": True,
            "message": "Дані отримано",
            "data": result
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Помилка: {str(e)}",
            "data": []
        }
# -----------------------------------------------------------------------------------------------------------------------