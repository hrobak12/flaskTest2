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
        SELECT status 
        FROM cartrg_status 
        WHERE cartridge_id = ? 
        ORDER BY time_updated DESC 
        LIMIT 1
    """, (cartridge_id,))
    last_status = cursor.fetchone()

    if last_status:
        # Якщо є подія, оновлюємо curr_status у Cartridges
        status_value = last_status[0]
        cursor.execute("""
            UPDATE cartridges 
            SET curr_status = ? 
            WHERE id = ?
        """, (status_value, cartridge_id))
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