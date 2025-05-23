from sqlalchemy import asc, desc
from models import *
from config import status_map

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