from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, request, send_file
from sqlalchemy import func, and_
from sqlalchemy.sql import text  # Додаємо імпорт text
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, RefillDept, PrinterModel, CustomerEquipment, Cartridges, CartridgeStatus, EventLog
from datetime import datetime
import bcrypt
from openpyxl import Workbook


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cartridge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Допоміжні функції
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def admin_required(f):
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


# Ініціалізація бази даних і створення початкового користувача
with app.app_context():
    db.create_all()
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_password = hash_password('admin')
        admin = User(username='admin', password=admin_password, humanname='Administrator', role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Користувач admin створений!")
    else:
        print("Користувач admin уже існує.")

        # Використовуємо text() для сирих SQL-запитів
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_cartridge_date ON cartrg_status (cartridge_id, date_ofchange)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_status ON cartrg_status (status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS idx_exec_dept ON cartrg_status (exec_dept)"))
        db.session.commit()
        print("Індекси створено або вже існують.")

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user, RefillDept=RefillDept)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password(password, user.password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Невірний логін або пароль')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# CRUD для RefillDept
@app.route('/refill_depts')
@login_required
def refill_depts():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Кількість записів на сторінці
    query = RefillDept.query.filter(RefillDept.deptname.ilike(f'%{search}%'))
    pagination = query.paginate(page=page, per_page=per_page)
    return render_template('refill_depts.html',
                           depts=pagination.items,
                           pagination=pagination,
                           search=search)

@app.route('/add_refill_dept', methods=['GET', 'POST'])
@admin_required
@login_required
def add_refill_dept():
    if request.method == 'POST':
        deptname = request.form['deptname']
        if RefillDept.query.filter_by(deptname=deptname).first():
            flash('Відділ із такою назвою вже існує!')
            return render_template('add_refill_dept.html')
        is_exec = int(request.form['is_exec'])
        dept = RefillDept(deptname=deptname, is_exec=is_exec, user_updated=current_user.id)
        db.session.add(dept)
        db.session.commit()
        flash('Відділ додано!')
        return redirect(url_for('refill_depts'))
    return render_template('add_refill_dept.html')

@app.route('/edit_refill_dept/<int:dept_id>', methods=['GET', 'POST'])
@admin_required
@login_required
def edit_refill_dept(dept_id):
    dept = RefillDept.query.get_or_404(dept_id)
    if request.method == 'POST':
        deptname = request.form['deptname']
        if RefillDept.query.filter(RefillDept.deptname == deptname, RefillDept.id != dept_id).first():
            flash('Відділ із такою назвою вже існує!')
            return render_template('edit_refill_dept.html', dept=dept)
        dept.deptname = deptname
        dept.is_exec = int(request.form['is_exec'])
        dept.user_updated = current_user.id
        db.session.commit()
        flash('Відділ оновлено!')
        return redirect(url_for('refill_depts'))
    return render_template('edit_refill_dept.html', dept=dept)

@app.route('/delete_refill_dept/<int:dept_id>', methods=['POST'])
@admin_required
@login_required
def delete_refill_dept(dept_id):
    dept = RefillDept.query.get_or_404(dept_id)
    db.session.delete(dept)
    event = EventLog(
        table_name='refill_dept',
        event_type=3,  # Видалення (новий тип події)
        user_updated=current_user.id
    )
    db.session.add(event)
    db.session.commit()
    flash('Відділ видалено!')
    return redirect(url_for('refill_depts'))

# CRUD для PrinterModel
@app.route('/printer_models')
@login_required
def printer_models():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Кількість записів на сторінці
    query = PrinterModel.query.filter(PrinterModel.model_name.ilike(f'%{search}%'))
    pagination = query.paginate(page=page, per_page=per_page)
    return render_template('printer_models.html',
                           models=pagination.items,
                           pagination=pagination,
                           search=search)

@app.route('/add_printer_model', methods=['GET', 'POST'])
@admin_required
@login_required
def add_printer_model():
    if request.method == 'POST':
        model_name = request.form['model_name']
        if PrinterModel.query.filter_by(model_name=model_name).first():
            flash('Модель із такою назвою вже існує!')
            return render_template('add_printer_model.html')
        ink_type = int(request.form['ink_type'])
        model = PrinterModel(model_name=model_name, ink_type=ink_type, user_updated=current_user.id)
        db.session.add(model)
        db.session.commit()
        flash('Модель принтера додано!')
        return redirect(url_for('printer_models'))
    return render_template('add_printer_model.html')

@app.route('/edit_printer_model/<int:model_id>', methods=['GET', 'POST'])
@admin_required
@login_required
def edit_printer_model(model_id):
    model = PrinterModel.query.get_or_404(model_id)
    if request.method == 'POST':
        model_name = request.form['model_name']
        if PrinterModel.query.filter(PrinterModel.model_name == model_name, PrinterModel.id != model_id).first():
            flash('Модель із такою назвою вже існує!')
            return render_template('edit_printer_model.html', model=model)
        model.model_name = model_name
        model.ink_type = int(request.form['ink_type'])
        model.user_updated = current_user.id
        db.session.commit()
        flash('Модель оновлено!')
        return redirect(url_for('printer_models'))
    return render_template('edit_printer_model.html', model=model)

@app.route('/delete_printer_model/<int:model_id>', methods=['POST'])
@admin_required
@login_required
def delete_printer_model(model_id):
    model = PrinterModel.query.get_or_404(model_id)
    db.session.delete(model)
    event = EventLog(
        table_name='model_print',
        event_type=3,  # Видалення (новий тип події)
        user_updated=current_user.id
    )
    db.session.add(event)
    db.session.commit()
    flash('Модель видалено!')
    return redirect(url_for('printer_models'))

# CRUD для CustomerEquipment
@app.route('/equipments')
@login_required
def equipments():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)  # Отримуємо номер сторінки з URL
    per_page = 10  # Кількість записів на сторінці (можете змінити)

    # Базовий запит із фільтром пошуку
    query = CustomerEquipment.query.filter(CustomerEquipment.serial_num.ilike(f'%{search}%'))
    # Додаємо пагінацію
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    equipments = pagination.items  # Обладнання на поточній сторінці

    return render_template('equipments.html',
                           RefillDept=RefillDept,
                           PrinterModel=PrinterModel,
                           equipments=equipments,
                           search=search,
                           pagination=pagination)

@app.route('/add_equipment', methods=['GET', 'POST'])
@admin_required
@login_required
def add_equipment():
    if request.method == 'POST':
        print_model = request.form['print_model']
        print_dept = request.form['print_dept']
        serial_num = request.form['serial_num']
        inventory_num = request.form['inventory_num']
        if CustomerEquipment.query.filter_by(inventory_num=inventory_num).first():
            flash('Обладнання з таким інвентарним номером уже існує!')
            return render_template('add_equipment.html', models=PrinterModel.query.all(), depts=RefillDept.query.all())
        equip = CustomerEquipment(
            print_model=print_model,
            print_dept=print_dept,
            serial_num=serial_num,
            inventory_num=inventory_num,
            user_updated=current_user.id
        )
        db.session.add(equip)
        db.session.commit()
        flash('Обладнання додано!')
        return redirect(url_for('equipments'))
    models = PrinterModel.query.all()
    depts = RefillDept.query.all()
    return render_template('add_equipment.html', models=models, depts=depts)

@app.route('/edit_equipment/<int:equip_id>', methods=['GET', 'POST'])
@admin_required
@login_required
def edit_equipment(equip_id):
    equip = CustomerEquipment.query.get_or_404(equip_id)
    if request.method == 'POST':
        print_model = request.form['print_model']
        print_dept = request.form['print_dept']
        serial_num = request.form['serial_num']
        inventory_num = request.form['inventory_num']
        if CustomerEquipment.query.filter(CustomerEquipment.inventory_num == inventory_num, CustomerEquipment.id != equip_id).first():
            flash('Обладнання з таким інвентарним номером уже існує!')
            return render_template('edit_equipment.html', equip=equip, models=PrinterModel.query.all(), depts=RefillDept.query.all())

        equip.print_model = print_model
        equip.print_dept = print_dept
        equip.serial_num = serial_num
        equip.inventory_num = inventory_num
        equip.user_updated = current_user.id

        db.session.commit()
        flash('Обладнання оновлено!')
        return redirect(url_for('equipments'))
    models = PrinterModel.query.all()
    depts = RefillDept.query.all()
    return render_template('edit_equipment.html', equip=equip, models=models, depts=depts)

@app.route('/delete_equipment/<int:equip_id>', methods=['POST'])
@admin_required
@login_required
def delete_equipment(equip_id):
    equip = CustomerEquipment.query.get_or_404(equip_id)
    db.session.delete(equip)
    db.session.commit()
    flash('Обладнання видалено!')
    return redirect(url_for('equipments'))

# CRUD для Cartridges
@app.route('/cartridges')
@login_required
def cartridges():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)  # Отримуємо номер сторінки з URL
    per_page = 10  # Кількість записів на сторінці (можете змінити)

    # Базовий запит із фільтром пошуку
    query = Cartridges.query.filter(Cartridges.serial_num.ilike(f'%{search}%'))
    # Додаємо пагінацію
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    cartridges = pagination.items  # Картриджі на поточній сторінці

    return render_template('cartridges.html',
                           RefillDept=RefillDept,
                           CustomerEquipment=CustomerEquipment,
                           PrinterModel=PrinterModel,
                           cartridges=cartridges,
                           search=search,
                           pagination=pagination)

@app.route('/add_cartridge', methods=['GET', 'POST'])
@login_required
def add_cartridge():
    if request.method == 'POST':
        serial_num = request.form['serial_num']
        if Cartridges.query.filter_by(serial_num=serial_num).first():
            flash('Картридж із таким серійним номером уже існує!')
            return render_template('add_cartridge.html', RefillDept=RefillDept, PrinterModel = PrinterModel, equipments=CustomerEquipment.query.all())
        in_printer = request.form['in_printer'] or None
        cartridge_model = request.form['cartridge_model']  # Текстове поле
        cartridge = Cartridges(
            serial_num=serial_num,
            in_printer=in_printer,
            cartridge_model=cartridge_model or None,  # Залишаємо None, якщо порожнє
            user_updated=current_user.id
        )
        db.session.add(cartridge)
        db.session.commit()
        flash('Картридж додано!')
        return redirect(url_for('cartridges'))
    equipments = CustomerEquipment.query.all()
    return render_template('add_cartridge.html', RefillDept=RefillDept, PrinterModel = PrinterModel, equipments=equipments)


@app.route('/edit_cartridge/<int:cartridge_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_cartridge(cartridge_id):
    cartridge = Cartridges.query.get_or_404(cartridge_id)
    if request.method == 'POST':
        serial_num = request.form['serial_num']
        # Перевірка унікальності серійного номера
        if Cartridges.query.filter(Cartridges.serial_num == serial_num, Cartridges.id != cartridge_id).first():
            flash('Картридж із таким серійним номером уже існує!')
            return render_template('edit_cartridge.html',
                                   RefillDept=RefillDept,
                                   PrinterModel=PrinterModel,
                                   cartridge=cartridge,
                                   equipments=CustomerEquipment.query.all())

        # Оновлення даних картриджа
        cartridge.serial_num = serial_num
        cartridge.in_printer = request.form['in_printer'] or None
        cartridge.cartridge_model = request.form['cartridge_model'] or None
        cartridge.user_updated = current_user.id
        cartridge.time_updated = datetime.now()

        # Додавання нової події в CartridgeStatus (якщо вказано статус)
        if 'status' in request.form and request.form['status']:
            new_status = CartridgeStatus(
                cartridge_id=cartridge.id,
                status=int(request.form['status']),
                parcel_track=request.form.get('parcel_track') or None,
                exec_dept=request.form.get('exec_dept') or None,
                user_updated=current_user.id,
                date_ofchange=datetime.now(),
                time_updated=datetime.now()
            )
            db.session.add(new_status)

        db.session.commit()
        flash('Картридж оновлено та подію додано (якщо вказано статус)!')
        return redirect(url_for('cartridges'))

    equipments = CustomerEquipment.query.all()
    return render_template('edit_cartridge.html',
                           RefillDept=RefillDept,
                           PrinterModel=PrinterModel,
                           cartridge=cartridge,
                           equipments=equipments)

@app.route('/delete_cartridge/<int:cartridge_id>', methods=['POST'])
@login_required
@admin_required
def delete_cartridge(cartridge_id):
    cartridge = Cartridges.query.get_or_404(cartridge_id)
    db.session.delete(cartridge)
    db.session.commit()
    flash('Картридж видалено!')
    return redirect(url_for('cartridges'))


@app.route('/cartridge_actions/<int:cartridge_id>', methods=['GET', 'POST'])
@login_required
def cartridge_actions(cartridge_id):
    cartridge = Cartridges.query.get_or_404(cartridge_id)
    statuses = CartridgeStatus.query.filter_by(cartridge_id=cartridge_id).order_by(CartridgeStatus.date_ofchange.desc()).all()
    return render_template('cartridge_actions.html',
                          cartridge=cartridge,
                          statuses=statuses,
                          Cartridges=Cartridges,
                          PrinterModel=PrinterModel,
                          RefillDept=RefillDept,
                          User=User)

@app.route('/send_to_refill/<int:cartridge_id>', methods=['POST'])
@login_required
def send_to_refill(cartridge_id):
    cartridge = Cartridges.query.get_or_404(cartridge_id)
    exec_dept_id = request.form['exec_dept_id']
    parcel_track = request.form.get('parcel_track', '')
    status = CartridgeStatus(
        status=1,  # "refill is pending"
        exec_dept=exec_dept_id,
        parcel_track=parcel_track,
        user_updated=current_user.id
    )
    cartridge.in_printer = None
    event = EventLog(
        table_name='cartridges',
        event_type=1,  # Зміна статусу
        user_updated=current_user.id
    )
    db.session.add(status)
    db.session.add(event)
    db.session.commit()
    flash('Картридж відправлено на заправку!')
    return redirect(url_for('cartridges'))

## Управління статусами картриджів
@app.route('/cartridge_status')
@login_required
def cartridge_status():
    search = request.args.get('search', '')
    if search:
        statuses = CartridgeStatus.query.join(Cartridges, Cartridges.id == CartridgeStatus.cartridge_id).filter(
            Cartridges.serial_num.ilike(f'%{search}%')
        ).all()
    else:
        statuses = CartridgeStatus.query.all()
    return render_template('cartridge_status.html',
                           statuses=statuses,
                           search=search,
                           Cartridges=Cartridges,  # Залишаємо для сумісності
                           RefillDept=RefillDept)  # Залишаємо для сумісності

@app.route('/update_status/<int:status_id>', methods=['POST'])
@login_required
def update_status(status_id):
    status = CartridgeStatus.query.get_or_404(status_id)
    new_status = int(request.form['status'])
    status.status = new_status
    status.user_updated = current_user.id
    status.time_updated = datetime.now()  # Оновлюємо час зміни
    event = EventLog(
        table_name='cartrg_status',
        event_type=2,  # Оновлення статусу
        user_updated=current_user.id
    )
    db.session.add(event)
    db.session.commit()
    flash('Статус оновлено!')
    return redirect(url_for('cartridge_status'))

@app.route('/delete_status/<int:status_id>', methods=['POST'])
@login_required
def delete_status(status_id):
    status = CartridgeStatus.query.get_or_404(status_id)
    db.session.delete(status)
    event = EventLog(
        table_name='cartrg_status',
        event_type=3,  # Видалення статусу (новий тип події)
        user_updated=current_user.id
    )
    db.session.add(event)
    db.session.commit()
    flash('Статус видалено!')
    return redirect(url_for('cartridge_status'))

# Перегляд логів подій
@app.route('/event_log')
@admin_required
@login_required
def event_log():
    table_filter = request.args.get('table_filter', '')
    type_filter = request.args.get('type_filter', '')
    query = EventLog.query
    if table_filter:
        query = query.filter(EventLog.table_name == table_filter)
    if type_filter:
        query = query.filter(EventLog.event_type == int(type_filter))
    logs = query.all()
    return render_template('event_log.html', User=User, logs=logs, table_filter=table_filter, type_filter=type_filter)

# Додавання користувача
@app.route('/users')
@admin_required
@login_required
def users():
    search = request.args.get('search', '')
    users_list = User.query.filter(User.username.ilike(f'%{search}%')).all()
    return render_template('users.html', users=users_list, search=search)

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        humanname = request.form['humanname']
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('Користувач із таким логіном уже існує!')
            return render_template('add_user.html')
        hashed_password = hash_password(password)
        new_user = User(username=username, password=hashed_password, humanname=humanname, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Користувача додано!')
        return redirect(url_for('users'))
    return render_template('add_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form['username']
        if User.query.filter(User.username == username, User.id != user_id).first():
            flash('Користувач із таким іменем уже існує!')
            return render_template('edit_user.html', user=user)
        user.username = username
        if request.form['password']:  # Оновлюємо пароль лише якщо введено
            user.password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.humanname = request.form['humanname']
        user.role = request.form['role']
        # Виправлення: явно перевіряємо наявність 'active'
        user.active = 'active' in request.form  # True якщо прапорець увімкнено, False якщо знято
        user.time_updated = datetime.now()
        db.session.commit()
        flash('Користувача оновлено!')
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Ви не можете видалити себе!')
        return redirect(url_for('users'))
    db.session.delete(user)
    db.session.commit()
    flash('Користувача видалено!')
    return redirect(url_for('users'))

@app.route('/add_cartridge_event', methods=['POST'])
@login_required
def add_cartridge_event():
    serial_num = request.form.get('serial_num')
    status = request.form.get('status')
    date_ofchange = request.form.get('date_ofchange')
    exec_dept = request.form.get('exec_dept') or None
    parcel_track = request.form.get('parcel_track') or None

    # Перевірка наявності картриджа
    cartridge = Cartridges.query.filter_by(serial_num=serial_num).first()
    if not cartridge:
        return jsonify({'success': False, 'message': 'Картридж із таким серійним номером не знайдено!'})

    # Додавання події в CartridgeStatus
    new_status = CartridgeStatus(
        cartridge_id=cartridge.id,
        status=int(status),
        date_ofchange=datetime.strptime(date_ofchange, '%Y-%m-%dT%H:%M'),
        parcel_track=parcel_track,
        exec_dept=exec_dept,
        user_updated=current_user.id,
        time_updated=datetime.now()
    )
    db.session.add(new_status)
    db.session.commit()

    return jsonify({'success': True})


@app.route('/processCartridge')
@login_required
def processCartridge():
    return render_template('processCartridge.html', user=current_user, RefillDept=RefillDept)

@app.route('/check_cartridge', methods=['POST'])
@login_required
def check_cartridge():
    data = request.get_json()
    serial_num = data.get('serial_num')

    # Перевірка наявності картриджа
    cartridge = Cartridges.query.filter_by(serial_num=serial_num).first()
    if not cartridge:
        return jsonify({'success': False, 'message': 'Картридж не знайдено!'})

    # Отримуємо останній статус із CartridgeStatus
    latest_status = CartridgeStatus.query.filter_by(cartridge_id=cartridge.id) \
        .order_by(CartridgeStatus.date_ofchange.desc()).first()

    return jsonify({
        'success': True,
        'latest_status': {
            'status': latest_status.status if latest_status else 0,
            'exec_dept': latest_status.exec_dept if latest_status else None,
            'parcel_track': latest_status.parcel_track if latest_status else None
        }
    })

#динамічний фільтр картриджів
@app.route('/api/cartridges', methods=['GET'])
@login_required
def api_cartridges():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query = Cartridges.query.filter(Cartridges.serial_num.ilike(f'%{search}%'))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    cartridges_data = []
    for cartridge in pagination.items:
        in_printer_info = None
        if cartridge.in_printer:
            equipment = CustomerEquipment.query.get(cartridge.in_printer)
            if equipment:
                printer_model = PrinterModel.query.get(equipment.print_model)
                dept = RefillDept.query.get(equipment.print_dept)
                in_printer_info = f"{printer_model.model_name} ({dept.deptname})"

        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'in_printer_info': in_printer_info
        })

    pagination_data = {
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'prev_num': pagination.prev_num,
        'next_num': pagination.next_num,
        'current_page': pagination.page,
        'pages': list(pagination.iter_pages(left_edge=1, left_current=2, right_current=2, right_edge=1)),
        'search': search
    }

    return jsonify({
        'cartridges': cartridges_data,
        'pagination': pagination_data
    })

@app.route('/api/equipments', methods=['GET'])
@login_required
def api_equipments():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Фільтруємо по назві моделі через join із PrinterModel
    if search:
        query = CustomerEquipment.query.join(PrinterModel, CustomerEquipment.print_model == PrinterModel.id)\
                                       .filter(PrinterModel.model_name.ilike(f'%{search}%'))
    else:
        query = CustomerEquipment.query

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    equipments_data = []
    for equip in pagination.items:
        # Використовуємо db.session.get замість query.get
        model = db.session.get(PrinterModel, equip.print_model) if equip.print_model else None
        dept = db.session.get(RefillDept, equip.print_dept) if equip.print_dept else None
        model_name = model.model_name if model else None
        dept_name = dept.deptname if dept else None
        equipments_data.append({
            'id': equip.id,
            'model_name': model_name,
            'dept_name': dept_name,
            'serial_num': equip.serial_num,
            'inventory_num': equip.inventory_num
        })

    pagination_data = {
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next,
        'prev_num': pagination.prev_num,
        'next_num': pagination.next_num,
        'current_page': pagination.page,
        'pages': list(pagination.iter_pages(left_edge=1, left_current=2, right_current=2, right_edge=1)),
        'search': search
    }

    return jsonify({
        'equipments': equipments_data,
        'pagination': pagination_data
    })

@app.route('/api/in_transit_cartridges', methods=['GET'])
@login_required
def api_in_transit_cartridges():
    # Отримуємо поточну дату
    current_date = datetime.utcnow()

    # Підзапит для визначення останньої події для кожного картриджа
    latest_status_subquery = db.session.query(CartridgeStatus.cartridge_id, func.max(CartridgeStatus.date_ofchange).label('max_date'))\
                                       .filter(CartridgeStatus.date_ofchange <= current_date)\
                                       .group_by(CartridgeStatus.cartridge_id)\
                                       .subquery()

    # Отримуємо картриджі зі статусом "В дорозі" (status = 3)
    in_transit_query = db.session.query(Cartridges, CartridgeStatus, RefillDept.deptname)\
                                 .join(CartridgeStatus, Cartridges.id == CartridgeStatus.cartridge_id)\
                                 .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                                 .join(latest_status_subquery,
                                       and_(Cartridges.id == latest_status_subquery.c.cartridge_id,
                                            CartridgeStatus.date_ofchange == latest_status_subquery.c.max_date))\
                                 .filter(CartridgeStatus.status == 3)

    cartridges_data = []
    for cartridge, status, dept_name in in_transit_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'date_ofchange': status.date_ofchange.isoformat(),
            'dept_name': dept_name,
            'parcel_track': status.parcel_track
        })

    return jsonify({'cartridges': cartridges_data})


# Новий ендпоінт для "На зберіганні"
@app.route('/api/in_storage_cartridges', methods=['GET'])
@login_required
def api_in_storage_cartridges():
    current_date = datetime.utcnow()
    latest_status_subquery = db.session.query(CartridgeStatus.cartridge_id, func.max(CartridgeStatus.date_ofchange).label('max_date'))\
                                       .filter(CartridgeStatus.date_ofchange <= current_date)\
                                       .group_by(CartridgeStatus.cartridge_id)\
                                       .subquery()
    in_storage_query = db.session.query(Cartridges, CartridgeStatus, RefillDept.deptname)\
                                 .join(CartridgeStatus, Cartridges.id == CartridgeStatus.cartridge_id)\
                                 .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                                 .join(latest_status_subquery,
                                       and_(Cartridges.id == latest_status_subquery.c.cartridge_id,
                                            CartridgeStatus.date_ofchange == latest_status_subquery.c.max_date))\
                                 .filter(CartridgeStatus.status == 6)\
                                 .order_by(Cartridges.cartridge_model.asc())  # Додаємо сортування
    cartridges_data = []
    for cartridge, status, dept_name in in_storage_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'date_ofchange': status.date_ofchange.isoformat(),
            'dept_name': dept_name,
            'parcel_track': status.parcel_track
        })
    return jsonify({'cartridges': cartridges_data})

#маршрут для отримання історії дій картриджа:
@app.route('/api/cartridge_history/<int:cartridge_id>', methods=['GET'])
@login_required
def api_cartridge_history(cartridge_id):
    history_query = db.session.query(CartridgeStatus, RefillDept.deptname, User.username)\
                              .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                              .outerjoin(User, CartridgeStatus.user_updated == User.id)\
                              .filter(CartridgeStatus.cartridge_id == cartridge_id)\
                              .order_by(CartridgeStatus.date_ofchange.desc())  # Сортуємо за датою, новіші першими
    history_data = []
    for status, dept_name, username in history_query.all():
        history_data.append({
            'date_ofchange': status.date_ofchange.isoformat(),
            'status': status.status,
            'dept_name': dept_name,
            'parcel_track': status.parcel_track,
            'user_login': username  # Змінено з user_login на username у відповідь, але в запиті правильно User.username
        })
    return jsonify({'history': history_data})

@app.route('/export/in_transit', methods=['GET'])
@login_required
def export_in_transit():
    # Отримуємо дані з API для "Картриджі в дорозі"
    current_date = datetime.utcnow()
    latest_status_subquery = db.session.query(CartridgeStatus.cartridge_id, func.max(CartridgeStatus.date_ofchange).label('max_date'))\
                                       .filter(CartridgeStatus.date_ofchange <= current_date)\
                                       .group_by(CartridgeStatus.cartridge_id)\
                                       .subquery()
    in_transit_query = db.session.query(Cartridges, CartridgeStatus, RefillDept.deptname)\
                                 .join(CartridgeStatus, Cartridges.id == CartridgeStatus.cartridge_id)\
                                 .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                                 .join(latest_status_subquery,
                                       and_(Cartridges.id == latest_status_subquery.c.cartridge_id,
                                            CartridgeStatus.date_ofchange == latest_status_subquery.c.max_date))\
                                 .filter(CartridgeStatus.status == 3)  # Статус "В дорозі"
    cartridges_data = []
    for cartridge, status, dept_name in in_transit_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model or 'Не вказано',
            'date_ofchange': status.date_ofchange.strftime('%Y-%m-%d %H:%M:%S'),
            'dept_name': dept_name or 'Не вказано',
            'parcel_track': status.parcel_track or 'Не вказано'
        })

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = "Картриджі в дорозі"
    headers = ["ID", "Серійний номер", "Модель картриджа", "Дата зміни", "Відділ", "Трек-номер"]
    ws.append(headers)
    for cartridge in cartridges_data:
        ws.append([cartridge['id'], cartridge['serial_num'], cartridge['cartridge_model'],
                   cartridge['date_ofchange'], cartridge['dept_name'], cartridge['parcel_track']])

    # Налаштування ширини колонок
    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                value_length = len(str(cell.value))
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)  # Запас 2 символи

    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))  # Межі: 10-50
        ws.column_dimensions[chr(65 + i)].width = adjusted_width

    # Зберігаємо файл у пам’яті
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Формуємо назву файлу
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Картриджі_в_дорозі_{timestamp}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

#маніпуляції з екселями
@app.route('/export/in_storage', methods=['GET'])
@login_required
def export_in_storage():
    # Отримуємо дані з API для "Картриджі на зберіганні"
    current_date = datetime.utcnow()
    latest_status_subquery = db.session.query(CartridgeStatus.cartridge_id, func.max(CartridgeStatus.date_ofchange).label('max_date'))\
                                       .filter(CartridgeStatus.date_ofchange <= current_date)\
                                       .group_by(CartridgeStatus.cartridge_id)\
                                       .subquery()
    in_storage_query = db.session.query(Cartridges, CartridgeStatus, RefillDept.deptname)\
                                 .join(CartridgeStatus, Cartridges.id == CartridgeStatus.cartridge_id)\
                                 .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                                 .join(latest_status_subquery,
                                       and_(Cartridges.id == latest_status_subquery.c.cartridge_id,
                                            CartridgeStatus.date_ofchange == latest_status_subquery.c.max_date))\
                                 .filter(CartridgeStatus.status == 6)  # Статус "На зберіганні"
    cartridges_data = []
    for cartridge, status, dept_name in in_storage_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model or 'Не вказано',
            'date_ofchange': status.date_ofchange.strftime('%Y-%m-%d %H:%M:%S'),
            'dept_name': dept_name or 'Не вказано',
            'parcel_track': status.parcel_track or 'Не вказано'
        })

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = "Картриджі на зберіганні"
    headers = ["ID", "Серійний номер", "Модель картриджа", "Дата зміни", "Відділ", "Трек-номер"]
    ws.append(headers)
    for cartridge in cartridges_data:
        ws.append([cartridge['id'], cartridge['serial_num'], cartridge['cartridge_model'],
                   cartridge['date_ofchange'], cartridge['dept_name'], cartridge['parcel_track']])

    # Налаштування ширини колонок
    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                value_length = len(str(cell.value))
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)  # Запас 2 символи

    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))  # Межі: 10-50
        ws.column_dimensions[chr(65 + i)].width = adjusted_width

    # Зберігаємо файл у пам’яті
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Формуємо назву файлу
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Картриджі_на_зберіганні_{timestamp}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/export/cartridge_history/<int:cartridge_id>', methods=['GET'])
@login_required
def export_cartridge_history(cartridge_id):
    # Отримуємо історію картриджа
    history_query = db.session.query(CartridgeStatus, RefillDept.deptname, User.username)\
                              .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                              .outerjoin(User, CartridgeStatus.user_updated == User.id)\
                              .filter(CartridgeStatus.cartridge_id == cartridge_id)\
                              .order_by(CartridgeStatus.date_ofchange.desc())
    history_data = []
    for status, dept_name, username in history_query.all():
        history_data.append({
            'date_ofchange': status.date_ofchange.strftime('%Y-%m-%d %H:%M:%S'),
            'status': status.status,
            'dept_name': dept_name or 'Не вказано',
            'parcel_track': status.parcel_track or 'Не вказано',
            'user_login': username or 'Не вказано'
        })

    # Отримуємо серійний номер картриджа для назви файлу з явною перевіркою типу
    cartridge = Cartridges.query.get_or_404(cartridge_id)
    serial_num = cartridge.serial_num
    if not isinstance(serial_num, str):
        serial_num = str(serial_num)
    serial_num = serial_num.replace('/', '_').replace('\\', '_')  # Замінюємо недопустимі символи

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = f"Історія_{serial_num}"
    headers = ["Дата", "Статус", "Відділ", "Трек-номер", "Оновлено користувачем"]
    ws.append(headers)
    status_map = {
        0: 'Порожній',
        1: 'Очікує заправки',
        2: 'Заправлений',
        3: 'В дорозі',
        4: 'Списаний',
        5: 'Одноразовий',
        6: 'На зберіганні'
    }
    for event in history_data:
        ws.append([event['date_ofchange'], status_map.get(event['status'], 'Невідомий'),
                   event['dept_name'], event['parcel_track'], event['user_login']])

    # Налаштування ширини колонок
    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                # Обчислюємо довжину вмісту (перетворюємо в строку)
                value_length = len(str(cell.value))
                # Оновлюємо максимальну ширину для колонки
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)  # Додаємо запас 2 символи

    # Встановлюємо ширину колонок із обмеженнями (мін. 10, макс. 50)
    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))  # Межі ширини: від 10 до 50
        ws.column_dimensions[chr(65 + i)].width = adjusted_width  # A=65, B=66 тощо

    # Зберігаємо файл у пам’яті
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Формуємо назву файлу
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Історія_{serial_num}_{timestamp}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)