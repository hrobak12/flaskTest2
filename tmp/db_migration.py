"""
CREATE TABLE cartridges_new (
	id INTEGER NOT NULL,
	serial_num VARCHAR(255) DEFAULT '0' NOT NULL,
	in_printer INTEGER,
	user_updated INTEGER NOT NULL,
	time_updated DATETIME DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	cartridge_model VARCHAR(255),
	cartrg_model_id INTEGER NOT NULL DEFAULT 1,
	curr_status INTEGER NOT NULL DEFAULT 0,
	curr_dept INTEGER NOT NULL DEFAULT 0,
	curr_parcel_track VARCHAR(13),
    PRIMARY KEY (id),
	FOREIGN KEY (in_printer) REFERENCES custmr_equip (id),
	FOREIGN KEY (user_updated) REFERENCES users (id),
	FOREIGN KEY (cartrg_model_id) REFERENCES cartrg_model (id)
);


INSERT INTO cartridges_new (id, serial_num, in_printer, user_updated, time_updated, cartridge_model, curr_status, curr_dept, curr_parcel_track)
SELECT id, serial_num, in_printer, user_updated, time_updated, cartridge_model, curr_status, curr_dept, curr_parcel_track
FROM cartridges





"""



# Ініціалізація бази даних і створення початкового користувача
#with app.app_context():
#    db.create_all()
#    admin_user = User.query.filter_by(username='admin').first()
#    if not admin_user:
#        admin_password = hash_password('admin')
#        admin = User(username='admin', password=admin_password, humanname='Administrator', role='admin')
#        db.session.add(admin)
#        db.session.commit()
#        print("Користувач admin створений!")
#    else:
#        print("Користувач admin уже існує.")

#        # Використовуємо text() для сирих SQL-запитів
#        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_cartridge_date ON cartrg_status (cartridge_id, date_ofchange)"))
#        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_status ON cartrg_status (status)"))
#        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_exec_dept ON cartrg_status (exec_dept)"))
#        db.session.commit()
#        print("Індекси створено або вже існують.")


#*********************************************************
with app.app_context():
    # Оновлення таблиці users
    try:
        # 1. Додаємо стовпець dept_id
        db.session.execute(text("ALTER TABLE users ADD COLUMN dept_id INTEGER"))
        print("Стовпець dept_id додано до таблиці users.")

        # 2. Заповнюємо dept_id значенням 1 для всіх існуючих записів
        db.session.execute(text("UPDATE users SET dept_id = 1 WHERE dept_id IS NULL"))
        print("Значення dept_id заповнено для існуючих записів.")

        # 3. Створюємо нову таблицю users_new
        db.session.execute(text("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY,
                username VARCHAR(30) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                humanname VARCHAR(60) NOT NULL,
                dept_id INTEGER NOT NULL,
                lastlogin DATETIME DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT TRUE,
                time_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                role VARCHAR(30) DEFAULT 'user',
                FOREIGN KEY (dept_id) REFERENCES refill_dept(id)
            )
        """))
        print("Таблицю users_new створено.")

        # 4. Переносимо дані
        db.session.execute(text("""
            INSERT INTO users_new (id, username, password, humanname, dept_id, lastlogin, active, time_updated, role)
            SELECT id, username, password, humanname, dept_id, lastlogin, active, time_updated, role
            FROM users
        """))
        print("Дані перенесено до users_new.")

        # 5. Видаляємо стару таблицю
        db.session.execute(text("DROP TABLE users"))
        print("Стару таблицю users видалено.")

        # 6. Перейменовуємо users_new на users
        db.session.execute(text("ALTER TABLE users_new RENAME TO users"))
        print("Таблицю users_new перейменовано на users.")

        db.session.commit()
        print("Базу даних успішно оновлено.")
    except Exception as e:
        db.session.rollback()
        print(f"Помилка при оновленні бази даних: {e}")
#*********************************************************
