import sqlite3
from datetime import datetime

# Підключення до бази даних
conn = sqlite3.connect('cartridge.db')  # Заміни 'your_database.db' на шлях до твоєї бази
cursor = conn.cursor()

# Отримуємо всі записи з таблиці Cartridges
cursor.execute("SELECT id FROM cartridges")
cartridges = cursor.fetchall()

# Лічильники для логування
updated_count = 0
no_status_count = 0

# Проходимо по кожному картриджу
for cartridge in cartridges:
    cartridge_id = cartridge[0]

    # Шукаємо останню подію для цього картриджа в CartridgeStatus
    cursor.execute("""
        SELECT exec_dept 
        FROM cartrg_status 
        WHERE cartridge_id = ? 
        ORDER BY time_updated DESC 
        LIMIT 1
    """, (cartridge_id,))
    last_exec_dept = cursor.fetchone()

    if last_exec_dept:
        # Якщо є подія, оновлюємо curr_status у Cartridges
        last_exec_dept_value = last_exec_dept[0]
        cursor.execute("""
            UPDATE cartridges 
            SET curr_dept = ? 
            WHERE id = ?
        """, (last_exec_dept_value, cartridge_id))
        updated_count += 1
    else:
        # Якщо подій немає, лишаємо curr_status як 0 (за замовчуванням)
        no_status_count += 1

# Зберігаємо зміни
conn.commit()

# Закриваємо з’єднання
conn.close()

# Логування результатів
print(f"Міграція завершена!")
print(f"Оновлено записів: {updated_count}")
print(f"Записів без статусу (залишено 0): {no_status_count}")