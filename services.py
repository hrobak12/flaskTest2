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