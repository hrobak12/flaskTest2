from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, RefillDept, PrinterModel, CustomerEquipment, Cartridges, CartridgeStatus, EventLog
from datetime import datetime
import bcrypt

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

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

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
    cartridges = Cartridges.query.filter(Cartridges.serial_num.ilike(f'%{search}%')).all()
    return render_template('cartridges.html',
                           RefillDept=RefillDept,
                           CustomerEquipment=CustomerEquipment,
                           PrinterModel=PrinterModel,  # Залишаємо для "У принтері"
                           cartridges=cartridges,
                           search=search)

@app.route('/add_cartridge', methods=['GET', 'POST'])
@login_required
@admin_required
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
        if Cartridges.query.filter(Cartridges.serial_num == serial_num, Cartridges.id != cartridge_id).first():
            flash('Картридж із таким серійним номером уже існує!')
            return render_template('edit_cartridge.html', RefillDept=RefillDept, PrinterModel = PrinterModel, cartridge=cartridge, equipments=CustomerEquipment.query.all())
        cartridge.serial_num = serial_num
        cartridge.in_printer = request.form['in_printer'] or None
        cartridge.cartridge_model = request.form['cartridge_model'] or None  # Текстове поле
        cartridge.user_updated = current_user.id
        db.session.commit()
        flash('Картридж оновлено!')
        return redirect(url_for('cartridges'))
    equipments = CustomerEquipment.query.all()
    return render_template('edit_cartridge.html', RefillDept=RefillDept, PrinterModel = PrinterModel, cartridge=cartridge, equipments=equipments)

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
                          RefillDept=RefillDept)

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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)