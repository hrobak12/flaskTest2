import os, secrets
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, request, Response, send_file
from sqlalchemy import func, and_
# from sqlalchemy.sql import text  # Додаємо імпорт text
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, RefillDept, PrinterModel, CustomerEquipment, Cartridges, CartridgeStatus, EventLog, CartridgeModel
from datetime import datetime
import bcrypt
from openpyxl import Workbook
from reportlab.lib.pagesizes import A4, mm #, A5, landscape, portrait
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
# from reportlab.graphics import renderPDF
from barcode import Code128
from barcode.writer import ImageWriter
from transliterate import translit


app = Flask(__name__)
# Тільки для розробки
# Виведе випадковий 64-символьний ключ, якщо інший не заданий в системі
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
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

#*************
#тут може бути скрипт міграції, якщо потрібно
#*************


@app.route('/')
@app.route('/index')
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
@login_required
@admin_required
def add_refill_dept():
    if request.method == 'POST':
        deptname = request.form['deptname']
        if RefillDept.query.filter_by(deptname=deptname).first():
            flash('Відділ із такою назвою вже існує!')
            return render_template('add_refill_dept.html')
        is_exec = int(request.form['is_exec'])
        dept = RefillDept(
            deptname=deptname,
            addr1=request.form.get('addr1', ''),  # Отримуємо addr1, за замовчуванням ''
            addr2=request.form.get('addr2', ''),  # Отримуємо addr2, за замовчуванням ''
            addr3=request.form.get('addr3', ''),  # Отримуємо addr3, за замовчуванням ''
            addr4=request.form.get('addr4', ''),  # Отримуємо addr4, за замовчуванням ''
            addr5=request.form.get('addr5', ''),  # Отримуємо addr5, за замовчуванням ''
            is_exec=is_exec,
            user_updated=current_user.id,
            time_updated=datetime.utcnow()  # Встановлюємо початковий час
        )
        db.session.add(dept)
        db.session.commit()
        flash('Відділ додано!')
        return redirect(url_for('refill_depts'))
    return render_template('add_refill_dept.html')


@app.route('/edit_refill_dept/<int:dept_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_refill_dept(dept_id):
    dept = RefillDept.query.get_or_404(dept_id)
    if request.method == 'POST':
        deptname = request.form['deptname']
        if RefillDept.query.filter(RefillDept.deptname == deptname, RefillDept.id != dept_id).first():
            flash('Відділ із такою назвою вже існує!')
            return render_template('edit_refill_dept.html', dept=dept)
        dept.deptname = deptname
        dept.addr1 = request.form.get('addr1', '')  # Отримуємо addr1, за замовчуванням ''
        dept.addr2 = request.form.get('addr2', '')  # Отримуємо addr2, за замовчуванням ''
        dept.addr3 = request.form.get('addr3', '')  # Отримуємо addr3, за замовчуванням ''
        dept.addr4 = request.form.get('addr4', '')  # Отримуємо addr4, за замовчуванням ''
        dept.addr5 = request.form.get('addr5', '')  # Отримуємо addr5, за замовчуванням ''
        dept.is_exec = int(request.form['is_exec'])
        dept.user_updated = current_user.id
        dept.time_updated = datetime.utcnow()  # Оновлюємо час зміни
        db.session.commit()
        flash('Відділ оновлено!')
        return redirect(url_for('refill_depts'))
    return render_template('edit_refill_dept.html', dept=dept)

@app.route('/delete_refill_dept/<int:dept_id>', methods=['POST'])
@login_required
@admin_required
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
@login_required
@admin_required
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
@login_required
@admin_required
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
@login_required
@admin_required
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
# Основний маршрут для відображення обладнання
@app.route('/equipments')
@login_required
def equipments():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    query = db.session.query(CustomerEquipment, PrinterModel.model_name, RefillDept.deptname)\
                      .outerjoin(PrinterModel, PrinterModel.id == CustomerEquipment.print_model)\
                      .outerjoin(RefillDept, RefillDept.id == CustomerEquipment.print_dept)\
                      .order_by(CustomerEquipment.id)

    if search:
        query = query.filter(CustomerEquipment.inventory_num.ilike(f'%{search}%'))

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    equipments = [(e[0], e[1], e[2]) for e in pagination.items]

    return render_template('equipments.html',
                           equipments=equipments,
                           search=search,
                           PrinterModel=PrinterModel,
                           RefillDept=RefillDept,
                           pagination=pagination)

@app.route('/add_equipment', methods=['GET', 'POST'])
@login_required
@admin_required
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
@login_required
@admin_required
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
@login_required
@admin_required
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
@admin_required
def add_cartridge():
    if request.method == 'POST':
        serial_num = request.form['serial_num']
        if Cartridges.query.filter_by(serial_num=serial_num).first():
            flash('Картридж із таким серійним номером уже існує!')
            return render_template('add_cartridge.html', RefillDept=RefillDept,
                                                         PrinterModel=PrinterModel,
                                                         CartridgeModel=CartridgeModel,
                                                         equipments=CustomerEquipment.query.all())
        in_printer = request.form['in_printer'] or None
        cartridge_model = request.form['cartridge_model'] or None
        cartrg_model_id = request.form['cartrg_model_id'] or None  # Нове поле
        cartridge = Cartridges(
            serial_num=serial_num,
            in_printer=in_printer,
            cartridge_model=cartridge_model,
            cartrg_model_id=cartrg_model_id,  # Додаємо нове поле
            user_updated=current_user.id
        )
        db.session.add(cartridge)
        db.session.commit()
        flash('Картридж додано!')
        return redirect(url_for('cartridges'))
    equipments = CustomerEquipment.query.all()
    return render_template('add_cartridge.html', RefillDept=RefillDept,
                                                 PrinterModel=PrinterModel,
                                                 CartridgeModel=CartridgeModel,
                                                 equipments=equipments)


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
                                   CartridgeModel=CartridgeModel,
                                   equipments=CustomerEquipment.query.all())

        # Оновлення даних картриджа
        cartridge.serial_num = serial_num
        cartridge.in_printer = request.form['in_printer'] or None
        cartridge.cartridge_model = request.form['cartridge_model'] or None
        cartridge.cartrg_model_id = request.form['cartrg_model_id'] or None  # Нове поле
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
                           CartridgeModel=CartridgeModel,
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

#deprecated. застаріле.
#@app.route('/send_to_refill/<int:cartridge_id>', methods=['POST'])
#@login_required
#def send_to_refill(cartridge_id):
#    cartridge = Cartridges.query.get_or_404(cartridge_id)
#    exec_dept_id = request.form['exec_dept_id']
#    parcel_track = request.form.get('parcel_track', '')
#    status = CartridgeStatus(
#        status=1,  # "refill is pending"
#        exec_dept=exec_dept_id,
#        parcel_track=parcel_track,
#        user_updated=current_user.id
#    )
#    cartridge.in_printer = None
#    event = EventLog(
#        table_name='cartridges',
#        event_type=1,  # Зміна статусу
#        user_updated=current_user.id
#    )
#    db.session.add(status)
#    db.session.add(event)
#    db.session.commit()
#    flash('Картридж відправлено на заправку!')
#    return redirect(url_for('cartridges'))

# Відображення подій обробки картриджів та керування ними
# Основний маршрут для відображення подій
@app.route('/cartridge_status')
@login_required
@admin_required
def cartridge_status():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    # Базовий запит із JOIN для оптимізації
    query = db.session.query(CartridgeStatus, Cartridges.serial_num, RefillDept.deptname)\
                      .outerjoin(Cartridges, Cartridges.id == CartridgeStatus.cartridge_id)\
                      .outerjoin(RefillDept, RefillDept.id == CartridgeStatus.exec_dept)\
                      .order_by(CartridgeStatus.date_ofchange.desc())

    if search:
        query = query.filter(Cartridges.serial_num.ilike(f'%{search}%'))

    # Пагінація
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    statuses = [(s[0], s[1] or 'Не вказано', s[2] or 'Не вказано') for s in pagination.items]

    return render_template('cartridge_status.html',
                           statuses=statuses,
                           search=search,
                           pagination=pagination)

@app.route('/update_status/<int:status_id>', methods=['POST'])
@login_required
@admin_required
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
@admin_required
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
@login_required
@admin_required
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
@login_required
@admin_required
def users():
    search = request.args.get('search', '')
    users_list = User.query.filter(User.username.ilike(f'%{search}%')).all()
    return render_template('users.html', users=users_list, search=search, RefillDept=RefillDept)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        humanname = request.form['humanname']
        role = request.form['role']
        dept_id = request.form['dept_id']  # Додаємо dept_id
        if User.query.filter_by(username=username).first():
            flash('Користувач із таким логіном уже існує!')
            return render_template('add_user.html', depts=RefillDept.query.all())
        hashed_password = hash_password(password)
        new_user = User(username=username, password=hashed_password, humanname=humanname, role=role, dept_id=dept_id)
        db.session.add(new_user)
        db.session.commit()
        flash('Користувача додано!')
        return redirect(url_for('users'))
    return render_template('add_user.html', depts=RefillDept.query.all())  # Передаємо список відділів

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form['username']
        if User.query.filter(User.username == username, User.id != user_id).first():
            flash('Користувач із таким іменем уже існує!')
            return render_template('edit_user.html', user=user, depts=RefillDept.query.all())
        user.username = username
        if request.form['password']:
            user.password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.humanname = request.form['humanname']
        user.role = request.form['role']
        user.dept_id = request.form['dept_id']  # Додаємо dept_id
        user.active = 'active' in request.form
        user.time_updated = datetime.now()
        db.session.commit()
        flash('Користувача оновлено!')
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user, depts=RefillDept.query.all())  # Передаємо список відділів

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Ви не можете видалити себе!')
        return redirect(url_for('users'))
    db.session.delete(user)
    db.session.commit()
    flash('Користувача видалено!')
    return redirect(url_for('users'))


# CRUD для CartridgeModel
@app.route('/cartridge_models')
@login_required
def cartridge_models():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Кількість записів на сторінці
    query = CartridgeModel.query.filter(CartridgeModel.model_name.ilike(f'%{search}%'))
    pagination = query.paginate(page=page, per_page=per_page)
    return render_template('cartridge_models.html',
                           models=pagination.items,
                           pagination=pagination,
                           search=search,
                           PrinterModel=PrinterModel)  # Додаємо PrinterModel для відображення назви принтера

@app.route('/add_cartridge_model', methods=['GET', 'POST'])
@login_required
@admin_required
def add_cartridge_model():
    if request.method == 'POST':
        model_name = request.form['model_name']
        if CartridgeModel.query.filter_by(model_name=model_name).first():
            flash('Модель із такою назвою вже існує!')
            return render_template('add_cartridge_model.html', printer_models=PrinterModel.query.all())
        model_type = int(request.form['model_type'])
        printer_model_id = request.form['printer_model_id'] or None  # Додаємо вибір моделі принтера
        model = CartridgeModel(
            model_name=model_name,
            model_type=model_type,
            printer_model_id=printer_model_id,  # Прив’язка до моделі принтера
            user_updated=current_user.id,
            time_updated=datetime.utcnow()
        )
        db.session.add(model)
        db.session.commit()
        flash('Модель картриджа додано!')
        return redirect(url_for('cartridge_models'))
    return render_template('add_cartridge_model.html', printer_models=PrinterModel.query.all())  # Передаємо список моделей принтерів

@app.route('/edit_cartridge_model/<int:model_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_cartridge_model(model_id):
    model = CartridgeModel.query.get_or_404(model_id)
    if request.method == 'POST':
        model_name = request.form['model_name']
        if CartridgeModel.query.filter(CartridgeModel.model_name == model_name, CartridgeModel.id != model_id).first():
            flash('Модель із такою назвою вже існує!')
            return render_template('edit_cartridge_model.html', model=model, printer_models=PrinterModel.query.all())
        model.model_name = model_name
        model.model_type = int(request.form['model_type'])
        model.printer_model_id = request.form['printer_model_id'] or None  # Оновлюємо прив’язку до принтера
        model.user_updated = current_user.id
        model.time_updated = datetime.utcnow()
        db.session.commit()
        flash('Модель оновлено!')
        return redirect(url_for('cartridge_models'))
    return render_template('edit_cartridge_model.html', model=model, printer_models=PrinterModel.query.all())  # Передаємо список моделей принтерів

@app.route('/delete_cartridge_model/<int:model_id>', methods=['POST'])
@login_required
@admin_required
def delete_cartridge_model(model_id):
    model = CartridgeModel.query.get_or_404(model_id)
    db.session.delete(model)
    event = EventLog(
        table_name='cartrg_model',
        event_type=3,  # Видалення
        user_updated=current_user.id
    )
    db.session.add(event)
    db.session.commit()
    flash('Модель видалено!')
    return redirect(url_for('cartridge_models'))


#**************************робота з картриджами**************************
@app.route('/processCartridge')
@login_required
def processCartridge():
    return render_template('processCartridge.html', user=current_user, RefillDept=RefillDept)

@app.route('/add_cartridge_event', methods=['POST'])
@login_required
def add_cartridge_event():
    serial_num = request.form.get('serial_num')
    status = request.form.get('status')
    exec_dept = request.form.get('exec_dept')
    printer = request.form.get('printer') or None
    parcel_track = request.form.get('parcel_track') or None

    # Перевірка наявності картриджа
    cartridge = Cartridges.query.filter_by(serial_num=serial_num).first()
    if not cartridge:
        return jsonify({'success': False, 'message': 'Картридж із таким серійним номером не знайдено!'})

    # Перевірка, чи вибрано відділ
    if not exec_dept:
        return jsonify({'success': False, 'message': 'Виберіть відділ!'})

    # Перевірка на дублювання статусу
    if cartridge.curr_status == int(status):
        return jsonify({'success': False, 'message': 'Цей статус уже встановлено для картриджа!'})


    # Додавання події в CartridgeStatus
    new_status = CartridgeStatus(
        cartridge_id=cartridge.id,
        status=int(status),
        date_ofchange=datetime.now(),  # Поточна дата з урахуванням часового поясу сервера
        parcel_track=parcel_track,
        exec_dept=int(exec_dept),
        user_updated=current_user.id,
        time_updated=datetime.now()
    )
    db.session.add(new_status)

    # Оновлення запису катриджа в Cartridges
    cartridge.curr_status = int(status)
    cartridge.curr_dept = int(exec_dept)
    cartridge.curr_parcel_track = parcel_track
    cartridge.in_printer = int(printer) if printer else None  # Оновлюємо принтер, якщо вибрано
    cartridge.user_updated = current_user.id
    cartridge.time_updated = datetime.now()


    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Помилка: {str(e)}'})

    return jsonify({'success': True})


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

    query = Cartridges.query.filter(Cartridges.serial_num.ilike(f'%{search}%')).order_by(Cartridges.cartridge_model.asc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    cartridges_data = []
    for cartridge in pagination.items:
        in_printer_info = None
        if cartridge.in_printer:
            equipment = db.session.get(CustomerEquipment, cartridge.in_printer)
#            equipment = CustomerEquipment.query.get(cartridge.in_printer)
            if equipment:
                printer_model = db.session.get(PrinterModel, equipment.print_model)
                dept = db.session.get(RefillDept, equipment.print_dept)
#                printer_model = PrinterModel.query.get(equipment.print_model)
#                dept = RefillDept.query.get(equipment.print_dept)
                in_printer_info = f"{printer_model.model_name} ({dept.deptname})"

        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'in_printer_info': in_printer_info,
            'curr_status': cartridge.curr_status  # Переконайся, що це є
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

#**************************робота з картриджами**************************

# API для асинхронного пошуку по інвентарному номеру
@app.route('/api/equipments', methods=['GET'])
@login_required
def api_equipments():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    query = db.session.query(CustomerEquipment, PrinterModel.model_name, RefillDept.deptname)\
                      .outerjoin(PrinterModel, PrinterModel.id == CustomerEquipment.print_model)\
                      .outerjoin(RefillDept, RefillDept.id == CustomerEquipment.print_dept)\
                      .order_by(CustomerEquipment.id)

    if search:
        query = query.filter(CustomerEquipment.inventory_num.ilike(f'%{search}%'))

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    equipments = [{
        'id': e[0].id,
        'model_name': e[1] or 'Не вказано',
        'dept_name': e[2] or 'Не вказано',
        'serial_num': e[0].serial_num,
        'inventory_num': e[0].inventory_num
    } for e in pagination.items]

    pagination_data = {
        'has_prev': pagination.has_prev,
        'prev_num': pagination.prev_num,
        'has_next': pagination.has_next,
        'next_num': pagination.next_num,
        'current_page': pagination.page,
        'pages': list(pagination.iter_pages()),
        'search': search
    }

    return jsonify({'equipments': equipments, 'pagination': pagination_data})

#Новий ендпоінт для принтерів
@app.route('/api/printers_by_dept/<int:dept_id>', methods=['GET'])
@login_required
def printers_by_dept(dept_id):
    printers = CustomerEquipment.query.filter_by(print_dept=dept_id).all()
    printers_data = [
        {
            'id': printer.id,
            'model_name': PrinterModel.query.get(printer.print_model).model_name
        }
        for printer in printers
    ]
    return jsonify({'printers': printers_data})

#тестовий ендпоінт для фільтрації статусу картриджів
@app.route('/api/cartridges_by_status/<int:cartridge_status>', methods=['GET'])
@login_required
def api_cartridges_by_status(cartridge_status):
    # Запит до Cartridges із фільтром по curr_status (1 або 6) і приєднанням RefillDept
    in_storage_query = db.session.query(Cartridges, RefillDept.deptname)\
                                 .outerjoin(RefillDept, Cartridges.curr_dept == RefillDept.id)\
                                 .filter(Cartridges.curr_status == cartridge_status) \
                                 .order_by(Cartridges.cartridge_model.asc())

    cartridges_data = []
    for cartridge, dept_name in in_storage_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'status': cartridge.curr_status,  # Беремо curr_status із Cartridges
            'date_ofchange': cartridge.time_updated.isoformat() if cartridge.time_updated else None,  # Використовуємо time_updated
            'dept_name': dept_name or 'Не вказано'
        })
    return jsonify({'cartridges': cartridges_data})



@app.route('/api/in_transit_cartridges', methods=['GET'])
@login_required
def api_in_transit_cartridges():
    # Запит до Cartridges із фільтром по curr_status == 3 і приєднанням RefillDept
    in_transit_query = db.session.query(Cartridges, RefillDept.deptname)\
                                 .outerjoin(RefillDept, Cartridges.curr_dept == RefillDept.id)\
                                 .filter(Cartridges.curr_status == 3)\
                                 .order_by(Cartridges.time_updated.desc())

    cartridges_data = []
    for cartridge, dept_name in in_transit_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'date_ofchange': cartridge.time_updated.isoformat() if cartridge.time_updated else None,
            'dept_name': dept_name or 'Не вказано',
            'parcel_track': cartridge.curr_parcel_track or 'Не вказано'
        })

    return jsonify({'cartridges': cartridges_data})


# Новий ендпоінт для "На зберіганні"

@app.route('/api/in_storage_cartridges', methods=['GET'])
@login_required
def api_in_storage_cartridges():
    # Запит до Cartridges із фільтром по curr_status (1 або 6) і приєднанням RefillDept
    in_storage_query = db.session.query(Cartridges, RefillDept.deptname)\
                                 .outerjoin(RefillDept, Cartridges.curr_dept == RefillDept.id)\
                                 .filter(Cartridges.curr_status.in_([1, 6]))\
                                 .order_by(Cartridges.cartridge_model.asc())

    cartridges_data = []
    for cartridge, dept_name in in_storage_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model,
            'status': cartridge.curr_status,  # Беремо curr_status із Cartridges
            'date_ofchange': cartridge.time_updated.isoformat() if cartridge.time_updated else None,  # Використовуємо time_updated
            'dept_name': dept_name or 'Не вказано'
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

# API для асинхронного пошуку подій обробки картриджів
@app.route('/api/cartridge_status', methods=['GET'])
@login_required
def api_cartridge_status():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    query = db.session.query(CartridgeStatus, Cartridges.serial_num, RefillDept.deptname)\
                      .outerjoin(Cartridges, Cartridges.id == CartridgeStatus.cartridge_id)\
                      .outerjoin(RefillDept, RefillDept.id == CartridgeStatus.exec_dept)\
                      .order_by(CartridgeStatus.date_ofchange.desc())

    if search:
        query = query.filter(Cartridges.serial_num.ilike(f'%{search}%'))

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    statuses = [{
        'id': s[0].id,
        'serial_num': s[1] or 'Не вказано',
        'status': s[0].status,
        'date_ofchange': s[0].date_ofchange.isoformat(),
        'parcel_track': s[0].parcel_track,
        'deptname': s[2] or 'Не вказано'
    } for s in pagination.items]

    pagination_data = {
        'has_prev': pagination.has_prev,
        'prev_num': pagination.prev_num,
        'has_next': pagination.has_next,
        'next_num': pagination.next_num,
        'current_page': pagination.page,
        'pages': list(pagination.iter_pages()),
        'search': search
    }

    return jsonify({'statuses': statuses, 'pagination': pagination_data})


#**********************************************************
#генерація наклейки на катридж

@app.route('/api/barcode/<int:cartridge_id>', methods=['GET'])
@login_required
def generate_barcode(cartridge_id):
    cartridge = Cartridges.query.get_or_404(cartridge_id)
    serial_num = str(cartridge.serial_num)  # Перетворення в рядок

    # Транслітерація кирилиці в латинські символи
    barcode_serial = translit(serial_num, 'uk', reversed=True) if any(c.isalpha() and ord(c) > 127 for c in serial_num) else serial_num


    # Налаштування розмірів
    label_width = 80 * mm
    label_height = 25 * mm
    gap = 2 * mm

    # Створення PDF у пам'яті
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=(label_width, label_height))

    # Логотип Укрпошти (чорно-білий)
    logo_path = os.path.join(app.static_folder, 'ukrposhta_logo.png')
    if os.path.exists(logo_path):
        c.drawImage(logo_path, 2 * mm, 2 * mm, width=20 * mm, height=20 * mm, preserveAspectRatio=True)

    # Генерація штрих-коду Code 128
    #barcode = Code128(serial_num, writer=ImageWriter())
    barcode = Code128(barcode_serial, writer=ImageWriter())

    barcode_path = os.path.join(app.static_folder, 'temp_barcode')
    barcode.save(barcode_path, options={"write_text": False, "module_height": 15, "module_width": 0.4})
    barcode_img_path = f"{barcode_path}.png"

    # Розміщення штрих-коду
    barcode_x = 25 * mm  # Відступ від логотипу
    barcode_y = 6 * mm  # Вертикальний відступ
    c.drawImage(barcode_img_path, barcode_x, barcode_y, width=50 * mm, height=15 * mm)

    # Текст під штрих-кодом
    c.setFont("Helvetica", 8)
    text_x = barcode_x + (50 * mm - c.stringWidth(serial_num, "Helvetica", 8)) / 2  # Центрування
    text_y = 2 * mm
    c.drawString(text_x, text_y, serial_num)

    # Завершення PDF
    c.showPage()
    c.save()

    # Очищення тимчасового файлу штрих-коду
    if os.path.exists(barcode_img_path):
        os.remove(barcode_img_path)

    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=f"barcode_{serial_num}.pdf")


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
    # Запит до Cartridges із фільтром по curr_status (1 або 6) і приєднанням RefillDept
    in_storage_query = db.session.query(Cartridges, RefillDept.deptname)\
                                 .outerjoin(RefillDept, Cartridges.curr_dept == RefillDept.id)\
                                 .filter(Cartridges.curr_status.in_([1, 6]))\
                                 .order_by(Cartridges.cartridge_model.asc())

    cartridges_data = []
    for cartridge, dept_name in in_storage_query.all():
        cartridges_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model or 'Не вказано',
            'date_ofchange': cartridge.time_updated.strftime('%Y-%m-%d %H:%M:%S') if cartridge.time_updated else 'Не вказано',
            'dept_name': dept_name or 'Не вказано',
            'status': 'На зберіганні (порожній)' if cartridge.curr_status == 1 else 'На зберіганні (заправлений)'  # Додаємо статус замість parcel_track
        })

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = "Картриджі на зберіганні"
    headers = ["ID", "Серійний номер", "Модель картриджа", "Дата зміни", "Відділ", "Статус"]
    ws.append(headers)
    for cartridge in cartridges_data:
        ws.append([cartridge['id'], cartridge['serial_num'], cartridge['cartridge_model'],
                   cartridge['date_ofchange'], cartridge['dept_name'], cartridge['status']])

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
        0: 'Не вказано',
        1: 'На зберіганні (порожній)',
        2: 'Відправлено в користування',
        3: 'Відправлено на заправку',
        4: 'Непридатний (списаний)',
        5: 'Одноразовий (фарба у банці)',
        6: 'На зберіганні (заправлений)'
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

# Маршрут для експорту в Excel подій обробки картриджів
# Маршрут для експорту в Excel (змінено на /export/cartridge_status)
@app.route('/export/cartridge_events', methods=['GET'])
@login_required
def export_cartridge_events():
    search = request.args.get('search', '')

    query = db.session.query(CartridgeStatus, Cartridges.serial_num, RefillDept.deptname)\
                      .outerjoin(Cartridges, Cartridges.id == CartridgeStatus.cartridge_id)\
                      .outerjoin(RefillDept, RefillDept.id == CartridgeStatus.exec_dept)\
                      .order_by(CartridgeStatus.date_ofchange.desc())
    if search:
        query = query.filter(Cartridges.serial_num.ilike(f'%{search}%'))

    statuses = [(s[0], s[1] or 'Не вказано', s[2] or 'Не вказано') for s in query.all()]

    wb = Workbook()
    ws = wb.active
    ws.title = "Події обробки картриджів"
    headers = ["ID", "Картридж", "Статус", "Дата зміни", "Трек-номер", "Відділ"]
    ws.append(headers)
    status_map = {
        0: 'Не вказано',
        1: 'На зберіганні (порожній)',
        2: 'Відправлено в користування',
        3: 'Відправлено на заправку',
        4: 'Непридатний (списаний)',
        5: 'Одноразовий (фарба у банці)',
        6: 'На зберіганні (заправлений)'
    }
    for status, serial_num, deptname in statuses:
        ws.append([status.id, serial_num, status_map.get(status.status, 'Невідомий'),
                   status.date_ofchange.strftime('%Y-%m-%d %H:%M:%S'),
                   status.parcel_track or 'Немає', deptname])

    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                value_length = len(str(cell.value))
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)

    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))
        ws.column_dimensions[chr(65 + i)].width = adjusted_width

    output = BytesIO()
    wb.save(output)
    output.seek(0)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Події_обробки_картриджів_{timestamp}.xlsx"
    return send_file(output, download_name=filename, as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# Маршрут для експорту в Excel
@app.route('/export/equipments_table', methods=['GET'])
@login_required
def export_equipments_table():
    search = request.args.get('search', '')

    query = db.session.query(CustomerEquipment, PrinterModel.model_name, RefillDept.deptname)\
                      .outerjoin(PrinterModel, PrinterModel.id == CustomerEquipment.print_model)\
                      .outerjoin(RefillDept, RefillDept.id == CustomerEquipment.print_dept)\
                      .order_by(CustomerEquipment.id)
    if search:
        query = query.filter(CustomerEquipment.inventory_num.ilike(f'%{search}%'))

    equipments = [(e[0], e[1] or 'Не вказано', e[2] or 'Не вказано') for e in query.all()]

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = "Список обладнання"
    headers = ["ID", "Модель", "Відділ", "Серійний номер", "Інвентарний номер"]
    ws.append(headers)
    for equip, model_name, deptname in equipments:
        ws.append([equip.id, model_name, deptname, equip.serial_num, equip.inventory_num])

    # Налаштування ширини колонок
    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                value_length = len(str(cell.value))
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)

    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))
        ws.column_dimensions[chr(65 + i)].width = adjusted_width

    # Зберігаємо файл
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Список_обладнання_{timestamp}.xlsx"
    return send_file(output, download_name=filename, as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/export/cartridges_table', methods=['GET'])
@login_required
def export_cartridges_table():
    search = request.args.get('search', '')

    query = Cartridges.query
    if search:
        query = query.filter(Cartridges.serial_num.ilike(f'%{search}%'))
    cartridges = query.all()

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = "Список картриджів"
    headers = ["ID", "Серійний номер", "Модель картриджа", "У принтері"]
    ws.append(headers)

    for cartridge in cartridges:
        in_printer_info = "Немає"
        if cartridge.in_printer:
            equipment = CustomerEquipment.query.get(cartridge.in_printer)
            if equipment:
                printer_model = PrinterModel.query.get(equipment.print_model)
                dept = RefillDept.query.get(equipment.print_dept)
                in_printer_info = f"{printer_model.model_name} ({dept.deptname})"
        ws.append([cartridge.id, cartridge.serial_num, cartridge.cartridge_model or "Не вказано", in_printer_info])

    # Налаштування ширини колонок
    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                value_length = len(str(cell.value))
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)

    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))
        ws.column_dimensions[chr(65 + i)].width = adjusted_width

    # Зберігаємо файл у пам’яті
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Формуємо назву файлу
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Список_картриджів_{timestamp}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

#*******************************************************************
#це тестовий pdf

# Реєстрація шрифту Times New Roman
pdfmetrics.registerFont(TTFont('TimesNewRoman', 'static/ttf/Times.ttf'))  # Шлях до файлу шрифту
pdfmetrics.registerFont(TTFont('TimesNewRomanBold', 'static/ttf/Timesbd.ttf'))  # Шлях до файлу шрифту

@app.route('/generate_shipping_label/<int:dept_id>', methods=['GET'])
@login_required
@admin_required
def generate_shipping_label(dept_id):
    # Отримуємо відділ відправника (з dept_id поточного користувача)
    sender_dept = RefillDept.query.get_or_404(current_user.dept_id)
    # Отримуємо відділ одержувача (з переданим dept_id)
    receiver_dept = RefillDept.query.get_or_404(dept_id)

    # Створюємо буфер для PDF
    buffer = BytesIO()
    textoffset = 20  # Відступ зверху

    # Ініціалізуємо PDF на розмір A4 у портретній орієнтації
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4  # 595 x 842 пунктів (портретна A4)
    half_height = height - height / 4.5

    # Заголовок "ОБЕРЕЖНО!!! НЕ КИДАТИ!!!"
    p.setFont("TimesNewRomanBold", 24)
    p.drawCentredString(width / 2, half_height + textoffset + 110, "ОБЕРЕЖНО!!!")
    p.drawCentredString(width / 2, half_height + textoffset + 80, "НЕ КИДАТИ!!!")

    # Адреса відправника (зліва, ближче до краю)
    p.setFont("TimesNewRoman", 12)
    p.drawString(20, half_height + textoffset - 10, "Відправник:")
    p.drawString(20, half_height + textoffset - 25, sender_dept.deptname or "")
    p.drawString(20, half_height + textoffset - 40, sender_dept.addr1 or "")
    p.drawString(20, half_height + textoffset - 55, sender_dept.addr2 or "")
    p.drawString(20, half_height + textoffset - 70, sender_dept.addr3 or "")
    p.drawString(20, half_height + textoffset - 85, sender_dept.addr4 or "")
    p.drawString(20, half_height + textoffset - 100, sender_dept.addr5 or "")

    horiz_offset=268
    # Адреса одержувача (справа, зсунено вліво на 1 см)
    p.drawString(width - horiz_offset, half_height + textoffset - 130, "Одержувач:")  # Змінено з -220 на -248
    p.drawString(width - horiz_offset, half_height + textoffset - 145, receiver_dept.deptname or "Не вказано")
    p.drawString(width - horiz_offset, half_height + textoffset - 160, receiver_dept.addr1 or "")
    p.drawString(width - horiz_offset, half_height + textoffset - 175, receiver_dept.addr2 or "")
    p.drawString(width - horiz_offset, half_height + textoffset - 190, receiver_dept.addr3 or "")
    p.drawString(width - horiz_offset, half_height + textoffset - 205, receiver_dept.addr4 or "")
    p.drawString(width - horiz_offset, half_height + textoffset - 220, receiver_dept.addr5 or "")

    # Номер заявки OTRS (знизу верхньої частини)
    p.drawString(20, half_height + textoffset - 240, "Номер заявки OTRS ______________________")

    # Завершуємо PDF
    p.showPage()
    p.save()

    # Повертаємо PDF як відповідь
    buffer.seek(0)
    return Response(buffer.getvalue(), mimetype='application/pdf',
                    headers={"Content-Disposition": "attachment;filename=shipping_label_"+str(dept_id)+".pdf"})

#****************** експериментально. звіт "що зроблено за день"
# Маршрут для відображення сторінки
@app.route('/report_period', methods=['GET'])
@login_required
def report_period():
    return render_template('report_period.html')


# API для отримання даних звіту
@app.route('/api/report_period', methods=['GET'])
@login_required
def api_report_period():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # Перетворюємо рядки дат у об'єкти datetime
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    except (ValueError, TypeError):
        return jsonify({'error': 'Неправильний формат дати. Використовуйте YYYY-MM-DD'}), 400

    # Базовий запит до CartridgeStatus
    query = db.session.query(CartridgeStatus, Cartridges, RefillDept.deptname, User.username)\
                      .join(Cartridges, CartridgeStatus.cartridge_id == Cartridges.id)\
                      .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                      .join(User, CartridgeStatus.user_updated == User.id)\
                      .filter(CartridgeStatus.date_ofchange.between(start_date, end_date))

    # Фільтр для не-адмінів
    if current_user.role != 'admin':  # Перевіряємо роль замість is_admin
        query = query.filter(CartridgeStatus.user_updated == current_user.id)

    # Виконуємо запит і формуємо дані
    report_data = []
    status_map = {
        0: 'Не вказано',
        1: 'На зберіганні (порожній)',
        2: 'Відправлено в користування',
        3: 'Відправлено на заправку',
        4: 'Непридатний (списаний)',
        5: 'Одноразовий (фарба у банці)',
        6: 'На зберіганні (заправлений)'
    }
    for status, cartridge, dept_name, username in query.order_by(CartridgeStatus.date_ofchange.desc()).all():
        report_data.append({
            'id': cartridge.id,
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model or 'Не вказано',
            'status': status_map[status.status],
            'date_ofchange': status.date_ofchange.isoformat(),
            'dept_name': dept_name or 'Не вказано',
            'user_login': username or 'Не вказано'  # Змінено з login на username
        })

    return jsonify({'report': report_data})

"""
# Хоч і нова функція, але поки що відключаю
# API для отримання даних звіту
@app.route('/api/report_period', methods=['GET'])
@login_required
def api_report_period():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # Перетворюємо рядки дат у об'єкти datetime
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    except (ValueError, TypeError):
        return jsonify({'error': 'Неправильний формат дати. Використовуйте YYYY-MM-DD'}), 400

    # Субзапит для отримання найсвіжішої події для кожного картриджа
    latest_status_subquery = db.session.query(CartridgeStatus.cartridge_id, func.max(CartridgeStatus.date_ofchange).label('max_date'))\
        .filter(CartridgeStatus.date_ofchange.between(start_date, end_date))\
        .group_by(CartridgeStatus.cartridge_id).subquery()

    # Основний запит із приєднанням до субзапиту
    query = db.session.query(CartridgeStatus, Cartridges, RefillDept.deptname, User.username)\
        .join(latest_status_subquery, (CartridgeStatus.cartridge_id == latest_status_subquery.c.cartridge_id) &
              (CartridgeStatus.date_ofchange == latest_status_subquery.c.max_date))\
        .join(Cartridges, CartridgeStatus.cartridge_id == Cartridges.id)\
        .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
        .join(User, CartridgeStatus.user_updated == User.id)

    # Фільтр для не-адмінів
    if current_user.role != 'admin':
        query = query.filter(CartridgeStatus.user_updated == current_user.id)

    # Сортування за датою (найсвіжіші зверху)
    query = query.order_by(CartridgeStatus.date_ofchange.desc())

    # Формуємо дані
    report_data = []
    status_map = {
        0: 'Не вказано',
        1: 'На зберіганні (порожній)',
        2: 'Відправлено в користування',
        3: 'Відправлено на заправку',
        4: 'Непридатний (списаний)',
        5: 'Одноразовий (фарба у банці)',
        6: 'На зберіганні (заправлений)'
    }
    for status, cartridge, dept_name, username in query.all():
        report_data.append({
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model or 'Не вказано',
            'status': status_map[status.status],
            'date_ofchange': status.date_ofchange.isoformat(),
            'dept_name': dept_name or 'Не вказано',
            'user_login': username or 'Не вказано'
        })

    return jsonify({'report': report_data})
"""
#******************************************************


@app.route('/export/report_period', methods=['GET'])
@login_required
def export_report_period():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    except (ValueError, TypeError):
        return "Неправильний формат дати", 400

    query = db.session.query(CartridgeStatus, Cartridges, RefillDept.deptname, User.username)\
                      .join(Cartridges, CartridgeStatus.cartridge_id == Cartridges.id)\
                      .outerjoin(RefillDept, CartridgeStatus.exec_dept == RefillDept.id)\
                      .join(User, CartridgeStatus.user_updated == User.id)\
                      .filter(CartridgeStatus.date_ofchange.between(start_date, end_date))

    if current_user.role != 'admin':  # Перевіряємо роль замість is_admin
        query = query.filter(CartridgeStatus.user_updated == current_user.id)

    report_data = []
    status_map = {
        0: 'Не вказано',
        1: 'На зберіганні (порожній)',
        2: 'Відправлено в користування',
        3: 'Відправлено на заправку',
        4: 'Непридатний (списаний)',
        5: 'Одноразовий (фарба у банці)',
        6: 'На зберіганні (заправлений)'
    }
    for status, cartridge, dept_name, username in query.order_by(CartridgeStatus.date_ofchange.asc()).all():
        report_data.append([
            cartridge.id,
            cartridge.serial_num,
            cartridge.cartridge_model or 'Не вказано',
            status_map[status.status],
            status.date_ofchange.strftime('%Y-%m-%d %H:%M:%S'),
            dept_name or 'Не вказано',
            username or 'Не вказано'  # Змінено з login на username
        ])

    # Створюємо Excel-файл
    wb = Workbook()
    ws = wb.active
    ws.title = "Звіт період"
    headers = ["ID", "Серійний номер", "Модель картриджа", "Статус", "Дата зміни", "Відділ", "Користувач"]
    ws.append(headers)
    for row in report_data:
        ws.append(row)

    # Налаштування ширини колонок
    column_widths = {}
    for row in ws.rows:
        for i, cell in enumerate(row):
            if cell.value:
                value_length = len(str(cell.value))
                column_widths[i] = max(column_widths.get(i, 10), value_length + 2)

    for i, width in column_widths.items():
        adjusted_width = max(10, min(width, 50))
        ws.column_dimensions[chr(65 + i)].width = adjusted_width

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Звіт_період_{timestamp}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

#****************** експериментально. звіт "що зроблено за день"
#****************** експериментально. масовий ввід ******************
@app.route('/mass_input')
@login_required
def mass_input():
    return render_template('mass_input.html', RefillDept=RefillDept)

@app.route('/mass_add_cartridge_events', methods=['POST'])
@login_required
def mass_add_cartridge_events():
    data = request.get_json()
    exec_dept = data.get('exec_dept')
    status = int(data.get('status'))
    serial_nums = data.get('serial_nums', [])
    parcel_track = data.get('parcel_track', '')
    printer = data.get('printer', None)

    if not exec_dept or not serial_nums:
        return jsonify({'success': False, 'message': 'Необхідно вказати відділ і хоча б один картридж!'}), 400

    # Перевірка відділу (для заправки лише is_exec=1)
    is_exec_required = status in [3, 6]  # На заправку або прийом заправлених
    dept = RefillDept.query.filter_by(id=exec_dept).first()
    if not dept or (is_exec_required and dept.is_exec != 1):
        return jsonify({'success': False, 'message': 'Недійсний відділ для цієї операції!'}), 400

    # Оптимізоване завантаження картриджів одним запитом
    cartridges = Cartridges.query.filter(Cartridges.serial_num.in_(serial_nums)).all()
    cartridge_dict = {c.serial_num: c for c in cartridges}

    report_data = []
    invalid_cartridges = []
    status_checks = {
        2: lambda c: c.curr_status == 6,  # Видача заправлених: лише із заправлених
        3: lambda c: c.curr_status == 1,  # Видача порожніх: лише із порожніх
        6: lambda c: c.curr_status == 3,  # Прийом заправлених: лише із "Відправлено на заправку"
        1: lambda c: c.curr_status == 2   # Прийом порожніх: із "Відправлено в користування"
    }

    for serial_num in serial_nums:
        cartridge = cartridge_dict.get(serial_num)
        if not cartridge:
            invalid_cartridges.append(serial_num)
            continue
        if not status_checks[status](cartridge):
            invalid_cartridges.append(serial_num)
            continue

        # Оновлення стану картриджа
        cartridge.curr_status = status
        cartridge.curr_dept = int(exec_dept)
        cartridge.curr_parcel_track = parcel_track if status == 3 else None
        cartridge.in_printer = int(printer) if printer and status == 2 else None
        cartridge.user_updated = current_user.id
        cartridge.time_updated = datetime.now()

        # Додавання події в історію
        new_status = CartridgeStatus(
            cartridge_id=cartridge.id,
            status=status,
            date_ofchange=datetime.now(),
            exec_dept=int(exec_dept),
            parcel_track=parcel_track if status == 3 else None,
            user_updated=current_user.id,
            time_updated=datetime.now()
        )
        db.session.add(new_status)
        report_data.append({
            'serial_num': cartridge.serial_num,
            'cartridge_model': cartridge.cartridge_model or 'Не вказано',
            'date_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    if invalid_cartridges:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Недійсні картриджі або статуси: {", ".join(invalid_cartridges)}'}), 400

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Помилка збереження: {str(e)}'}), 500

    # Генерація PDF-звіту
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("TimesNewRoman", 12)
    status_titles = {
        2: "Видача заправлених картриджів",
        3: "Видача порожніх картриджів на заправку",
        6: "Прийом заправлених картриджів",
        1: "Прийом порожніх картриджів"
    }
    p.drawString(100, 800, f"Звіт: {status_titles.get(status, 'Масова операція')}")
    p.drawString(100, 780, f"Відділ: {dept.deptname}")
    p.drawString(100, 760, f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y = 740
    p.drawString(50, y, "Серійний номер")
    p.drawString(200, y, "Модель картриджа")
    p.drawString(350, y, "Дата/Час")
    y -= 20

    for item in report_data:
        if y < 50:
            p.showPage()
            p.setFont("TimesNewRoman", 12)
            y = 800
        p.drawString(50, y, item['serial_num'])
        p.drawString(200, y, item['cartridge_model'])
        p.drawString(350, y, item['date_time'])
        y -= 20

    p.showPage()
    p.save()
    buffer.seek(0)

    return Response(buffer.getvalue(), mimetype='application/pdf',
                    headers={"Content-Disposition": f"attachment;filename=mass_operation_{status}_report.pdf"})



@app.route('/api/barcodes_all', methods=['GET'])
@login_required
@admin_required
def generate_all_barcodes():
    search_query = request.args.get('search', '')
    cartridges = Cartridges.query.filter(Cartridges.serial_num.ilike(f'%{search_query}%')).all()

    if not cartridges:
        return jsonify({"error": "Немає картриджів для генерації"}), 404

    # Налаштування розмірів
    label_width = 80 * mm
    label_height = 25 * mm
    gap = 2 * mm

    # Створення PDF у пам'яті
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=(label_width, label_height))

    for cartridge in cartridges:
        serial_num = str(cartridge.serial_num)
        barcode_serial = translit(serial_num, 'uk', reversed=True) if any(c.isalpha() and ord(c) > 127 for c in serial_num) else serial_num

        # Логотип Укрпошти
        logo_path = os.path.join(app.static_folder, 'ukrposhta_logo.png')
        if os.path.exists(logo_path):
            c.drawImage(logo_path, 2 * mm, 2 * mm, width=20 * mm, height=20 * mm, preserveAspectRatio=True)

        # Генерація штрих-коду Code 128
        barcode = Code128(barcode_serial, writer=ImageWriter())
        barcode_path = os.path.join(app.static_folder, f'temp_barcode_{cartridge.id}')
        barcode.save(barcode_path, options={"write_text": False, "module_height": 15, "module_width": 0.4})
        barcode_img_path = f"{barcode_path}.png"

        # Розміщення штрих-коду
        barcode_x = 25 * mm
        barcode_y = 6 * mm
        c.drawImage(barcode_img_path, barcode_x, barcode_y, width=50 * mm, height=15 * mm)

        # Текст під штрих-кодом
        c.setFont("Helvetica", 8)
        text_x = barcode_x + (50 * mm - c.stringWidth(serial_num, "Helvetica", 8)) / 2
        text_y = 2 * mm
        c.drawString(text_x, text_y, serial_num)

        # Нова сторінка для наступного картриджа
        c.showPage()

        # Очищення тимчасового файлу
        if os.path.exists(barcode_img_path):
            os.remove(barcode_img_path)

    # Завершення PDF
    c.save()
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=f"all_barcodes_{datetime.now().strftime('%Y-%m-%d')}.pdf")


@app.route('/api/departments', methods=['GET'])
@login_required
def get_departments():
    departments = RefillDept.query.all()
    return jsonify({
        'departments': [
            {'id': dept.id, 'deptname': dept.deptname, 'is_exec': dept.is_exec}
            for dept in departments
        ]
    })


@app.route('/update_cartridge_barcodes', methods=['POST'])
@login_required
def update_cartridge_barcodes():
    data = request.get_json()
    cartridge_ids = data.get('cartridge_ids', [])
    barcode = data.get('barcode', '').strip()

    if not cartridge_ids or not barcode:
        return jsonify({'success': False, 'message': 'Необхідно вказати картриджі та штрих-код'}), 400

    try:
        for cartridge_id in cartridge_ids:
            # Оновлюємо parcel_track для останньої події зі статусом 3 у CartridgeStatus
            latest_status = CartridgeStatus.query.filter_by(cartridge_id=cartridge_id, status=3).order_by(CartridgeStatus.date_ofchange.desc()).first()
            if latest_status:
                latest_status.parcel_track = barcode
                latest_status.time_updated = datetime.now()
                latest_status.user_updated = current_user.id

            # Оновлюємо curr_parcel_track у таблиці Cartridges
            cartridge = Cartridges.query.get(cartridge_id)
            if cartridge:
                cartridge.curr_parcel_track = barcode
            else:
                # Якщо картридж не знайдено, логувати помилку, але не переривати цикл
                current_app.logger.error(f"Картридж з ID {cartridge_id} не знайдено в таблиці Cartridges")

        db.session.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)